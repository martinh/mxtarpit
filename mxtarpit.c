/*
 * Copyright (c) 2017 Martin Hedenfalk <martin@bzero.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <resolv.h> /* b64_pton */

struct mbuf {
	char data[1024];
	size_t len;
	size_t ofs;
};

enum smtp_state {
	smtp_sending_banner,
	smtp_helo,
	smtp_auth_login_username,
	smtp_auth_login_password,
	smtp_auth_plain,
	smtp_data_response,
	smtp_data,
	smtp_close,
};

struct conn {
	int fd;
	struct ev_io read_watcher;
	struct ev_io write_watcher;
	struct ev_timer stutter;
	struct mbuf inbuf;
	struct mbuf outbuf;
	enum smtp_state state;
	ev_tstamp connected_at;
	int is_spam;
	int got_data;

	char addr[64];
	char helo[64];
	char from[128];
	char rcpt[128];
	unsigned char auth[64];
	unsigned char pass[64];
};

struct domain {
	char *name;
	char **users;
	size_t nusers;
	int accept_any_user;
};

struct app_globals {
	struct ev_loop *loop;
#define MAX_LISTENERS 16
	struct ev_io listeners[MAX_LISTENERS];
	size_t num_listeners;
	float initial_stutter_interval;
	float spam_stutter_interval;
	struct {
		char *banner;
		char *helo;
		char *mail;
		char *rcpt;
		char *data;
		char *rset;
		char *quit;
		char *tempfail;
	} resp;

	const char *tagsep;
	char hostname[256];
	struct domain *domains;
	size_t ndomains;
	int loglevel;
	struct passwd *pw;
	int allow_mail_from_my_domains:1;
	int foreground:1;
} app;

static void
fatal(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "mxtarpit: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void
logmsg(int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (app.foreground) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		if (prio <= LOG_INFO) {
			va_end(ap);
			va_start(ap, fmt);
			vsyslog(prio, fmt, ap);
		}
	} else if (app.loglevel >= prio) {
		vsyslog(prio, fmt, ap);
	}
	va_end(ap);
}

#define debug(fmt, ...) logmsg(LOG_DEBUG, (fmt), ##__VA_ARGS__)
#define info(fmt, ...) logmsg(LOG_INFO, (fmt), ##__VA_ARGS__)
#define warn(fmt, ...) logmsg(LOG_WARNING, (fmt), ##__VA_ARGS__)

static void
fd_nonblock(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		warn("fcntl(O_NONBLOCK): %s", strerror(errno));
	}
}

static char *
mklower(char *str)
{
	int i;
	for (i = 0; str && str[i]; i++) {
		str[i] = tolower(str[i]);
	}
	return str;
}

static int
cmp_domain(const void *a, const void *b)
{
	const struct domain *da = a;
	const struct domain *db = b;
	return strcmp(da->name, db->name);
}

static int
cmp_user(const void *a, const void *b)
{
	const char * const *ua = a;
	const char * const *ub = b;
	return strcmp(*ua, *ub);
}

static struct domain *
find_domain(const char *domainname)
{
	struct domain find;
	find.name = (char *)domainname;
	return bsearch(&find, app.domains, app.ndomains,
		       sizeof(*app.domains), cmp_domain);
}

static int
is_valid_user(struct domain *d, const char *user)
{
	if (d->accept_any_user) {
		return 1;
	}
	return bsearch(&user, d->users, d->nusers,
		       sizeof(*d->users), cmp_user) != NULL;
}

static void
add_address(char *domainname, char *user)
{
	struct domain *d;
	int sort_domains = 0;

	mklower(domainname);
	mklower(user);
	d = find_domain(domainname);
	if (d == NULL) {
		if ((app.ndomains+1) > SIZE_MAX / sizeof(*app.domains)) {
			/* Overflow. */
			fatal("Too many domains");
		}
		app.domains = realloc(app.domains,
				      (app.ndomains+1) *
				      sizeof(*app.domains));
		if (app.domains == NULL) {
			fatal("realloc: %s", strerror(errno));
		}
		d = &app.domains[app.ndomains++];
		memset(d, 0, sizeof(*d));
		d->name = strdup(domainname);
		if (d->name == NULL) {
			fatal("strdup: %s", strerror(errno));
		}
		sort_domains = 1;
	}

	if (user == NULL || *user == '\0') {
		/* Accept any users in domain. */
		d->accept_any_user = 1;
		free(d->users);
		d->users = NULL;
		d->nusers = 0;
	}

	if (!d->accept_any_user) {
		if ((d->nusers+1) > SIZE_MAX / sizeof(*d->users)) {
			/* Overflow. */
			fatal("Too many addresses in domain %s", d->name);
		}
		d->users = realloc(d->users, (d->nusers + 1) *
				    sizeof(*d->users));
		if (d->users == NULL) {
			fatal("realloc: %s", strerror(errno));
		}
		d->users[d->nusers] = strdup(user);
		if (d->users[d->nusers] == NULL) {
			fatal("strdup: %s", strerror(errno));
		}
		d->nusers++;
	}

	if (sort_domains) {
		qsort(app.domains, app.ndomains,
		      sizeof(*app.domains), cmp_domain);
	}
}

static int
load_addresses(const char *addrfile, char *errbuf, size_t errlen)
{
	char buf[1024];
	FILE *fp;
	int ret = 0;
	size_t i;

	fp = fopen(addrfile, "r");
	if (fp == NULL) {
		snprintf(errbuf, errlen, "%s", strerror(errno));
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		size_t n;
		char *p = buf;
		char *user;
		if (buf[strlen(buf) - 1] != '\n') {
			snprintf(errbuf, errlen, "Line too long");
			ret = -1;
			break;
		}
		p += strspn(buf, " \t\n");
		if (*p == '#' || *p == '\0') {
			continue;
		}
		n = strcspn(p, " \t\n");
		p[n] = '\0';
		user = strsep(&p, "@");
		if (!p) {
			snprintf(errbuf, errlen, "Invalid address: %s", user);
			ret = -1;
			break;
		}
		add_address(p, user);
	}

	if (ferror(fp)) {
		snprintf(errbuf, errlen, "%s", strerror(errno));
		ret = -1;
	}
	fclose(fp);

	for (i = 0; i < app.ndomains; i++) {
		struct domain *d = &app.domains[i];
		qsort(d->users, d->nusers, sizeof(*d->users), cmp_user);
		debug("got %zu addresses in domain %s", d->nusers, d->name);
	}

	return ret;
}

static int
is_helo_fqdn(struct conn *conn, char *args)
{
	char *p;
	size_t len;
	int nlabels;
	int digits_only;

	len = strcspn(args, " ");
	if (len == 0) {
		/* Missing hostname. */
		debug("%d: missing hostname", conn->fd);
		return 0;
	}
	args[len] = '\0';

	/* We're deliberately not parsing address literals. No proper mail
	 * server should use an address literal. */

	mklower(args);
	debug("%d: validating FQDN [%s]", conn->fd, args);
	for (p = args, len = 0, nlabels = 1, digits_only = 1; *p; p++) {
		if (*p == '.') {
			if (len < 1 || len > 63) {
				debug("%d: label length is %zu", conn->fd, len);
				return 0;
			}
			if (p[1] != '\0') {
				/* Don't count the trailing dot. */
				nlabels++;
			}
		} else {
			int c = *p;
			int letter = (c >= 'a' && c <= 'z');
			int digit = (c >= '0' && c <= '9');
			if (letter || digit ||
			    (c == '-' && len > 0 &&
			     p[1] != '\0' && p[1] != '.')) {
				if (!digit) {
					digits_only = 0;
				}
				len++;
			} else {
				return 0;
			}
		}
	}
	if (digits_only) {
		debug("%d: tld is digits only", conn->fd);
		return 0;
	}
	return nlabels > 1;
}

static void
conn_is_spam(struct conn *conn)
{
	conn->stutter.repeat = app.spam_stutter_interval;
	conn->is_spam = 1;
}

static void
check_helo_fqdn(struct conn *conn, char *args)
{
	if (args == NULL || !is_helo_fqdn(conn, args)) {
		debug("%d: NOT a valid FQDN in HELO/EHLO", conn->fd);
		conn_is_spam(conn);
	}
	snprintf(conn->helo, sizeof(conn->helo), "%s", args ? args : "<empty>");
}

static void
check_address(struct conn *conn, char *addr, char *prefix, int reverse_path,
	      char *savebuf, size_t savelen)
{
	struct domain *d;
	char *user;
	size_t n;

	snprintf(savebuf, savelen, "(invalid)");

	mklower(addr);

	/* Check prefix (to: or from:). */
	while (*prefix) {
		if (addr == NULL || *addr++ != *prefix++) {
			goto bad_syntax;
		}
	}

	/* Extract <address> part. */
	addr += strspn(addr, " ");
	if (*addr++ != '<') {
		goto bad_syntax;
	}
	n = strcspn(addr, ">");
	if (addr[n] != '>') {
		goto bad_syntax;
	}
	addr[n] = '\0';

	snprintf(savebuf, savelen, "%s", addr ? addr : "");

	/* Empty Reverse-Path <> is ok. */
	if (reverse_path && addr[0] == '\0') {
		return;
	}

	/* Split user part and domain name. */
	user = strsep(&addr, "@");
	if (addr == NULL) {
		goto bad_syntax;
	}

	/* Skip address checks if not configured. */
	if (app.ndomains == 0) {
		return;
	}

	d = find_domain(addr);
	if (!d) {
		if (reverse_path) {
			/* Don't try to validate external addresses. */
			return;
		}
		debug("%d: Invalid domain name [%s]", conn->fd, addr);
		conn_is_spam(conn);
		return;
	} else if (reverse_path && !app.allow_mail_from_my_domains) {
		/* No legitimate mail from our domains should ever be sent from
		 * the real MXs. */
		debug("%d: Fake sender from our domain [%s]", conn->fd, addr);
		conn_is_spam(conn);
		return;
	}

	/* Ignore trailing tag in user part (user+tag@domain). */
	user[strcspn(user, app.tagsep)] = '\0';

	if (!is_valid_user(d, user)) {
		debug("%d: Invalid recipient [%s@%s]",
		      conn->fd, user, d->name);
		conn_is_spam(conn);
		return;
	}

	return;
bad_syntax:
	debug("%d: Bad address syntax", conn->fd);
	conn_is_spam(conn);
}

static void
check_sender(struct conn *conn, char *args)
{
	return check_address(conn, args, "from:", 1,
			     conn->from, sizeof(conn->from));
}

static void
check_recipient(struct conn *conn, char *args)
{
	return check_address(conn, args, "to:", 0,
			     conn->rcpt, sizeof(conn->rcpt));
}

static int
conn_vput(struct conn *conn, const char *fmt, va_list ap)
{
	struct mbuf *mbuf;
	size_t left;
	int res;

	mbuf = &conn->outbuf;
	left = sizeof(mbuf->data) - mbuf->len;
	res = vsnprintf(mbuf->data + mbuf->len, left, fmt, ap);

	if (res < 0) {
		/* Output or encoding error? */
		conn->state = smtp_close;
		return -1;
	} else if ((size_t)res >= left) {
		/* Output truncated. */
		debug("%d: output truncated", conn->fd);
		conn->state = smtp_close;
		return -1;
	} else {
		mbuf->len += res;
		return res;
	}
}

static void
conn_puts(struct conn *conn, const char *fmt, ...)
{
	va_list ap;
	int res;

	va_start(ap, fmt);
	res = conn_vput(conn, fmt, ap);
	va_end(ap);
	if (res == -1) {
		return;
	}

	debug("%d: -> [%.*s]", conn->fd,
	      res, conn->outbuf.data + conn->outbuf.len - res);

	va_start(ap, fmt);
	res = conn_vput(conn, "\r\n", ap);
	va_end(ap);
	if (res == -1) {
		return;
	}

	if (conn->stutter.repeat > 0) {
		debug("%d: stuttering with interval %.2fs",
		      conn->fd, conn->stutter.repeat);
		ev_timer_start(app.loop, &conn->stutter);
	} else {
		ev_io_start(app.loop, &conn->write_watcher);
	}
}

static char *
conn_readline(struct conn *conn, size_t *lenp)
{
	char *p = conn->inbuf.data;
	size_t i;

	for (i = 0; i < conn->inbuf.len; i++) {
		if (p[i] == '\r' && i + 1 < conn->inbuf.len && p[i+1] == '\n') {
			p[i] = '\0';
			*lenp = i + 2;
			return p + strspn(p, " ");
		}
	}
	return NULL;
}

static void
conn_close(struct conn *conn)
{
	int minutes, seconds;

	seconds = (int)(ev_now(app.loop) - conn->connected_at);
	minutes = seconds / 60;
	seconds -= minutes * 60;
	info("%d: %c %s (%s) duration %dm:%ds,"
	     " mail from: <%s> rcpt to: <%s>",
	     conn->fd,
	     conn->is_spam ? 'S' : (conn->rcpt[0] == '\0' ? '?' : 'H'),
	     conn->addr, conn->helo,
	     minutes, seconds,
	     conn->from, conn->rcpt);
	close(conn->fd);
	ev_io_stop(app.loop, &conn->read_watcher);
	ev_io_stop(app.loop, &conn->write_watcher);
	ev_timer_stop(app.loop, &conn->stutter);
	free(conn);
}

static void
conn_auth_done(struct conn *conn)
{
	info("%d: S %s (%s) authenticated as <%s> with password <%s>",
	     conn->fd, conn->addr, conn->helo, conn->auth, conn->pass);
	conn_puts(conn, "235 Authentication success simulated");
	conn->state = smtp_helo;
}

static void
conn_auth_plain(struct conn *conn, const char *data)
{
	unsigned char plain[128];
	int len;

	debug("auth plain [%s]", data);

	memset(plain, 0, sizeof(plain));
	len = b64_pton(data, plain, sizeof(plain) - 1);
	if (len > 0) {
		char *auth = (char *)plain;
		char *pass;
		char *nil;

		snprintf((char *)conn->auth, sizeof(conn->auth), "%s", auth);

		nil = memchr(auth, '\0', len);
		if (nil) {
			if ((nil - auth) < len) {
				pass = nil + 1;
				snprintf((char *)conn->pass,
					 sizeof(conn->pass), "%s", pass);
			}
		}
	}
	conn_auth_done(conn);
}

static void
conn_auth(struct conn *conn, char *args)
{
	char *method;

	/* No legitimate mail server should ever try AUTH. */
	conn_is_spam(conn);

	method = mklower(strsep(&args, " "));
	if (method == NULL) {
		conn_puts(conn, "503 Missing authentication mechanism");
	} else if (strcmp(method, "login") == 0) {
		conn_puts(conn, "334 VXNlcm5hbWU6"); /* Username */
		conn->state = smtp_auth_login_username;
	} else if (strcmp(method, "plain") == 0) {
		if (args) {
			conn_auth_plain(conn, args);
		} else {
			conn_puts(conn, "334 Please continue authenticating");
			conn->state = smtp_auth_plain;
		}
	} else {
		conn_puts(conn, "503 Unsupported authentication mechanism");
	}
}

static void
conn_process_command(struct conn *conn, char *line)
{
	char *cmd, *args = NULL;

	cmd = strsep(&line, " ");
	if (line) {
		line += strspn(line, " ");
		if (*line) {
			args = line;
		}
	}

	mklower(cmd);
	debug("%d: got cmd [%s] args [%s]", conn->fd, cmd, args);

	if (strcmp(cmd, "helo") == 0) {
		check_helo_fqdn(conn, args);
		conn_puts(conn, "250 %s %s", app.hostname, app.resp.helo);
	} else if (strcmp(cmd, "ehlo") == 0) {
		check_helo_fqdn(conn, args);
		conn_puts(conn, "250-%s %s", app.hostname, app.resp.helo);
		conn_puts(conn, "250-8BITMIME");
		conn_puts(conn, "250 AUTH LOGIN PLAIN");
	} else if (strcmp(cmd, "auth") == 0) {
		conn_auth(conn, args);
	} else if (strcmp(cmd, "mail") == 0) {
		check_sender(conn, args);
		conn_puts(conn, "250 %s", app.resp.mail);
	} else if (strcmp(cmd, "rcpt") == 0) {
		check_recipient(conn, args);
		conn_puts(conn, "250 %s", app.resp.rcpt);
	} else if (strcmp(cmd, "data") == 0) {
		conn->got_data = 1;
		if (conn->from[0] == '\0' || conn->rcpt[0] == '\0') {
			/* No sender or recipient. */
			conn_is_spam(conn);
		}
		if (0 && conn->is_spam) {
			conn_puts(conn, "354 %s", app.resp.data);
			conn->state = smtp_data_response;
		} else {
			if (!conn->is_spam) {
				/* If we get to DATA without any RFC violation
				 * or other weirdness, disable stuttering, and
				 * close the connection right after the
				 * response is flushed. */
				conn->stutter.repeat = 0;
				conn->state = smtp_close;
			}
			conn_puts(conn, "451 %s", app.resp.tempfail);
		}
	} else if (strcmp(cmd, "rset") == 0) {
		conn_puts(conn, "250 %s", app.resp.rset);
	} else if (strcmp(cmd, "noop") == 0) {
		conn_puts(conn, "250 OK");
	} else if (strcmp(cmd, "quit") == 0) {
		if (!conn->got_data) {
			conn_is_spam(conn);
		}
		conn_puts(conn, "221 %s", app.resp.quit);
		conn->state = smtp_close;
	} else if (cmd[0] == '\0') {
		conn_puts(conn, "500 Bad syntax");
	} else {
		conn_puts(conn, "502 Command not recognized");
	}
}

static int
conn_process_line(struct conn *conn)
{
	size_t len;
	char *line;
	int res;

	line = conn_readline(conn, &len);
	if (line == NULL) {
		/* Wait for more data. */
		if (conn->inbuf.len == sizeof(conn->inbuf.data)) {
			/* Line too long. */
			debug("%d: Line too long", conn);
			return -1;
		} else {
			return 1;
		}
	}
	debug("%d: <- [%s]", conn->fd, line);

	switch (conn->state) {
	case smtp_helo:
		conn_process_command(conn, line);
		break;
	case smtp_data:
		if (strcmp(line, ".") == 0) {
			conn_puts(conn, "451 %s", app.resp.tempfail);
			conn->state = smtp_helo;
		}
		break;
	case smtp_auth_login_username:
		memset(conn->auth, 0, sizeof(conn->auth));
		res = b64_pton(line, conn->auth, sizeof(conn->auth) - 1);
		if (res == -1) {
			debug("%d: invalid base64 encoded username", conn->fd);
			conn->auth[0] = '\0';
		}
		conn_puts(conn, "334 UGFzc3dvcmQ6"); /* Password: */
		conn->state = smtp_auth_login_password;
		break;
	case smtp_auth_login_password:
		memset(conn->pass, 0, sizeof(conn->pass));
		res = b64_pton(line, conn->pass, sizeof(conn->pass) - 1);
		if (res == -1) {
			debug("%d: invalid base64 encoded password", conn->fd);
			conn->pass[0] = '\0';
		}
		conn_auth_done(conn);
		break;
	case smtp_auth_plain:
		conn_auth_plain(conn, line);
		break;
	case smtp_sending_banner:
	case smtp_data_response:
	case smtp_close:
		fatal("unexpected state %d", conn->state);
		break;
	}

	/* Consume the processed line. */
	memmove(conn->inbuf.data, conn->inbuf.data + len, conn->inbuf.len - len);
	conn->inbuf.len -= len;

	return 0;
}

static void
conn_process(struct conn *conn)
{
	for (;;) {
		switch (conn_process_line(conn)) {
		case -1:
			conn_close(conn);
			return;
		case 1:
			/* Incomplete line received. */
			ev_io_start(app.loop, &conn->read_watcher);
			return;
		case 0:
			/* One line received and processed. */
			break;
		}

		if (conn->state == smtp_data) {
			/* Continue processing all received data. */
		} else {
			/* Do not read more until response flushed. */
			ev_io_stop(app.loop, &conn->read_watcher);
			break;
		}
	}
}

static void
conn_readable(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct conn *conn = w->data;
	ssize_t res;

	res = read(w->fd, conn->inbuf.data + conn->inbuf.len,
		   sizeof(conn->inbuf.data) - conn->inbuf.len);
	if (res < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		debug("%d: read: %s", conn->fd, strerror(errno));
		return;
	} else if (res == 0) {
		conn_close(conn);
		return;
	} else {
		conn->inbuf.len += res;

		if (conn->state == smtp_sending_banner) {
			debug("%d: received data before banner sent", w->fd);
			conn_is_spam(conn);
			return;
		}
	}

	conn_process(conn);
}

static void
conn_write(struct conn *conn, size_t maxbytes)
{
	size_t nbytes;
	ssize_t res;

	nbytes = conn->outbuf.len - conn->outbuf.ofs;
	if (nbytes > maxbytes) {
		nbytes = maxbytes;
	}

	res = write(conn->fd, conn->outbuf.data + conn->outbuf.ofs, nbytes);
	if (res < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		if (errno != EPIPE) {
			warn("%d: write: %s", conn->fd, strerror(errno));
		}
		conn_close(conn);
		return;
	} else {
		conn->outbuf.ofs += res;
	}

	if (conn->outbuf.len == conn->outbuf.ofs) {
		int s = (int)(ev_now(app.loop) - conn->connected_at);
		debug("%d: %zu byte in outbuf flushed at %ds",
		      conn->fd, conn->outbuf.len, s);

		ev_timer_stop(app.loop, &conn->stutter);
		ev_io_stop(app.loop, &conn->write_watcher);

		if (conn->state == smtp_close) {
			conn_close(conn);
			return;
		}

		if (conn->state == smtp_sending_banner) {
			conn->state = smtp_helo;
		} else if (conn->state == smtp_data_response) {
			conn->state = smtp_data;
		}
		conn->outbuf.ofs = 0;
		conn->outbuf.len = 0;
		conn_process(conn);
	}
}

static void
conn_stutter(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	struct conn *conn = w->data;
	size_t maxbytes = 1;

	if (w->repeat == 0) {
		maxbytes = SIZE_MAX;
	}
	conn_write(conn, maxbytes);
}

static void
conn_writable(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct conn *conn = w->data;
	conn_write(conn, sizeof(conn->outbuf.data));
}

static void
conn_accept(struct ev_loop *loop, struct ev_io *w, int revents)
{
	struct conn *conn;
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	socklen_t salen = sizeof(ss);
	int afd;

	afd = accept(w->fd, sa, &salen);
	if (afd == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		} else if (errno == EMFILE || errno == ENFILE) {
			/* See comment in libev manual. */
		}
		debug("%d: accept: %s", w->fd, strerror(errno));
		return;
	}

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		debug("malloc: %s", strerror(errno));
		close(afd);
		return;
	}

	getnameinfo(sa, salen, conn->addr, sizeof(conn->addr),
		    NULL, 0, NI_NUMERICHOST);

	{
		time_t now;
		struct tm *tm;
		now = ev_now(loop);
		tm = localtime(&now);
		debug("%d: got connection from %s at %s",
		      afd, conn->addr, asctime(tm));
	}

	conn->is_spam = 0;
	conn->fd = afd;
	conn->connected_at = ev_now(loop);

	fd_nonblock(afd);

	ev_io_init(&conn->read_watcher, conn_readable, afd, EV_READ);

	ev_io_init(&conn->write_watcher, conn_writable, afd, EV_WRITE);
	ev_timer_init(&conn->stutter, conn_stutter,
		      app.initial_stutter_interval,
		      app.initial_stutter_interval);
	conn->read_watcher.data = conn;
	conn->write_watcher.data = conn;
	conn->stutter.data = conn;

	conn->state = smtp_sending_banner;
	conn_puts(conn, "220 %s %s", app.hostname, app.resp.banner);

	/* Start the read watcher so we can detect clients that send data
	 * before initial banner received (which is an RFC violation). */
	ev_io_start(app.loop, &conn->read_watcher);
}

int
main(int argc, char **argv)
{
	const char *host = NULL, *port = "25";
	struct addrinfo hints, *ai0, *ai;
	const char *user = "nobody";
	const char *jail = "/var/empty";
	const char *addrfile = NULL;
	char *endptr;
	int fd;
	int res;
	int c;

	app.loglevel = LOG_INFO;
	app.tagsep = "+";
	app.loop = EV_DEFAULT;
	if (gethostname(app.hostname, sizeof(app.hostname)) != 0) {
		snprintf(app.hostname, sizeof(app.hostname), "localhost");
	}
	app.initial_stutter_interval = 0.25;
	app.spam_stutter_interval = 3;

	app.resp.banner = "ESMTP Fake Backup MX Tarpit Service";
	app.resp.helo = "Hello, pleased to meet you."
		" Welcome to this deliberately slow electronic mail service.";
	app.resp.mail = "Yeah that is probably fine."
		" Please continue attempting delivery of your message.";
	app.resp.rcpt = "Any recipient is accepted here."
		" No actual delivery is ever attempted anyway.";
	app.resp.data = "Enter your message, end with a dot on a line by itself."
		        " The message will be discarded.";
	app.resp.rset = "Okay. It is acceptable to start over again now.";
	app.resp.quit = "Goodbye. Thank you for your patience.";
	app.resp.tempfail = "Temporary failure."
		" You are welcome to try your message again some other time.";

	openlog("mxtarpit", LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	while ((c = getopt(argc, argv, "Aa:d:Fj:l:n:p:s:S:t:u:")) != -1) {
		switch (c) {
		case 'A':
			app.allow_mail_from_my_domains = 1;
			break;
		case 'a':
			addrfile = optarg;
			break;
		case 'd':
			add_address(optarg, NULL);
			break;
		case 'F':
			app.foreground = 1;
			break;
		case 'j':
			jail = optarg;
			break;
		case 'l':
			host = optarg;
			break;
		case 'n':
			snprintf(app.hostname, sizeof(app.hostname),
				 "%s", optarg);
			break;
		case 'p':
			port = optarg;
			break;
		case 's':
			app.initial_stutter_interval = strtof(optarg, &endptr);
			if (app.initial_stutter_interval < 0 ||
			    app.initial_stutter_interval > 10 ||
			    *endptr != '\0') {
				fatal("Invalid stutter interval: %s", optarg);
			}
			break;
		case 'S':
			app.spam_stutter_interval = strtof(optarg, &endptr);
			if (app.spam_stutter_interval < 0 ||
			    app.spam_stutter_interval > 10 ||
			    *endptr != '\0') {
				fatal("Invalid stutter interval: %s", optarg);
			}
			break;
		case 't':
			app.tagsep = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case '?':
			return 1;
		}
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	app.pw = getpwnam(user);
	if (app.pw == NULL) {
		fatal("%s: %s", user, strerror(errno));
	}

	res = getaddrinfo(host, port, &hints, &ai0);
	if (res != 0) {
		fatal("%s:%s: %s", host, port, gai_strerror(res));
	}

	/* Let write(2) return EPIPE. */
	signal(SIGPIPE, SIG_IGN);

	/* Set time zone information before chrooting. */
	tzset();

	/* Open listening sockets in the main process only. */
	for (ai = ai0; ai; ai = ai->ai_next) {
		char sabuf[256];
		int on;

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd == -1) {
			continue;
		}

		on = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef IPV6_V6ONLY
		if (ai->ai_family == AF_INET6) {
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				   &on, sizeof(on));
		}
#endif
		getnameinfo(ai->ai_addr, ai->ai_addrlen, sabuf, sizeof(sabuf),
			    NULL, 0, NI_NUMERICHOST);

		res = bind(fd, ai->ai_addr, ai->ai_addrlen);
		if (res == 0) {
			res = listen(fd, 10);
		}
		if (res == 0) {
			struct ev_io *w;
			fd_nonblock(fd);
			w = &app.listeners[app.num_listeners++];
			ev_io_init(w, conn_accept, fd, EV_READ);
			ev_io_start(app.loop, w);
			info("Listening on [%s]:%s", sabuf, port);
			if (app.num_listeners == MAX_LISTENERS) {
				break;
			}
		} else {
			info("[%s]:%s: %s", sabuf, port, strerror(errno));
			close(fd);
			continue;
		}
	}
	freeaddrinfo(ai0);

	if (app.num_listeners == 0) {
		if (host) {
			fatal("Unable to bind to %s:%s: %s",
			      host, port, strerror(errno));
		} else {
			fatal("Unable to bind to port %s: %s",
			      port, strerror(errno));
		}
	}

	if (addrfile) {
		char errbuf[256];
		if (load_addresses(addrfile, errbuf, sizeof(errbuf)) == -1) {
			fatal("Unable to load addresses from '%s': %s",
			      addrfile, errbuf);
		}
	}

	/* Chroot to an empty directory and drop privileges. */
	if (chroot(jail) == -1 || chdir("/") == -1) {
		fatal("%s: %s", jail, strerror(errno));
	}
	if (setgid(app.pw->pw_gid) == -1 || setuid(app.pw->pw_uid) == -1) {
		fatal("%s: %s", app.pw->pw_name, strerror(errno));
	}

	if (!app.foreground) {
		if (daemon(0, 0) == -1) {
			fatal("daemon: %s", strerror(errno));
		}
	}

#ifdef __OpenBSD__
	pledge("stdio inet", NULL);
#endif

	ev_run(app.loop, 0);

	return 0;
}
