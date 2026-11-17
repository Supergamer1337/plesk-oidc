# Plesk OIDC

Plesk OIDC is a Plesk extension to allow admins from a group automatically create and login to personal administration accounts, leaving the authentication layer to a generic OIDC provider.

As this is a security extension, the number one thing we do not compromise on is SECURITY. We should do everything our power to make sure the extension is secure and safe for use in production environments. No regressions should ever introduce security issues.

## On Writing Code

When writing code for this project there are a few guidlines.

First of all, default to using *no comments*. Agents (and humans!) can read the code. Comments should only suprising or unintuitive behaviour you cannot get from reading the surrouding code or relevant call sites.

If you are writing comments, then they should be short, concise and succint. They should be easy to read, following simplified technical english and most of the time aim to be one line. A comment should never be more than 4 lines. They should avoid weird punctuation styles like using ";", ":" and dashes.

When desiging the code, understand the real constraint, then fight for the smallest model that makes the correct behavior unsurprising. Channel both "measure twice, cut once" and "yagni". Fight scope creep. Try to honor the dev's intent in both a minimal and realistic fashion.