# mxtarpit

`mxtarpit` is a fake SMTP server. It participates in the SMTP dialogue and, if
the client is determined to be a spammer, communicates very slowly. Spammers
are detected either by trying to relay mail to non-final domains, violating the
RFC, or being blacklisted. It never accepts any email, but instead responds
with a 451 Temporary failure.

Some spammers violates the RFC and connects to listed MXs in the wrong order.
Running `mxtarpit` as a low-priority backup MX can avoid these hitting the
regular mail server. Hopefully it also slows them down quite a bit.

`mxtarpit` should not be run on a machine where you care about IP reputation,
as it acts like an open relay.

Here is what a typical SMTP conversation looks like with a spammer connection:

    -> [220 mail.example.com ESMTP Fake Backup MX Tarpit Service]
    <- [EHLO win-f1ciet00a47]
    -> [250-mail.example.com Hello, pleased to meet you. Welcome to this deliberately slow electronic mail service.]
    -> [250-8BITMIME]
    -> [250 AUTH LOGIN PLAIN]
    <- [MAIL FROM:<lksblijmbc@example.com>]
    -> [250 Yeah that is probably fine. Please continue attempting delivery of your message.]
    <- [RCPT TO:<martin@example.com>]
    -> [250 Any recipient is accepted here. No actual delivery is ever attempted anyway.]
    <- [DATA]
    -> [451 Temporary failure. You are welcome to try your message again some other time.]
    <- [QUIT]
    -> [221 Goodbye. Thank you for your patience.]

The above conversation took 24 minutes of spammer time, but very little
resources on the server.
