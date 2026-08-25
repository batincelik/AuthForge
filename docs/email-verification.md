# Email verification

Registration creates an unverified user, a hashed 256-bit single-use token, and an encrypted outbox entry in one database transaction. The worker decrypts only for delivery and destroys the payload after Mailpit/SMTP accepts it. Verification locks and consumes the row before activating the user. Resend invalidates outstanding tokens and is rate limited.

