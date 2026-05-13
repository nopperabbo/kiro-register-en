"""
Mail-provider abstraction layer — swap between temporary-mailbox services.

Usage:
    from mail_providers import get_provider, list_providers
    provider = get_provider("shiromail", base_url="http://...", api_key="...")
    email = provider.create_mailbox()
    otp = provider.wait_otp(timeout=90)

Adding a new provider:
    1. Create a new .py file under mail_providers/
    2. Subclass MailProvider and implement the three abstract methods
    3. Register the class in the PROVIDERS dict below
"""
from .base import MailProvider
from .shiromail import ShiroMailProvider
from .yydsmail import YydsMailProvider
from .gsuite_imap import GsuiteImapProvider

PROVIDERS: dict[str, type[MailProvider]] = {
    "shiromail": ShiroMailProvider,
    "yydsmail": YydsMailProvider,
    "gsuite_imap": GsuiteImapProvider,
}


def get_provider(name: str, **kwargs) -> MailProvider:
    """Instantiate a mail provider by registered name."""
    cls = PROVIDERS.get(name)
    if not cls:
        raise ValueError(f"Unknown mail provider: {name}, available: {list(PROVIDERS.keys())}")
    return cls(**kwargs)


def list_providers() -> list[dict]:
    """Return metadata for every registered mail provider."""
    return [{"name": cls.name, "display_name": cls.display_name} for cls in PROVIDERS.values()]
