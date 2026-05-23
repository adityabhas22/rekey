"""Mail / OTP fetcher adapters."""

from rekey.adapters.mail.applescript_rule import MailEvent, MailRuleReceiver
from rekey.adapters.mail.webmail_tab import WebmailTabOTPFetcher

__all__ = ["MailEvent", "MailRuleReceiver", "WebmailTabOTPFetcher"]
