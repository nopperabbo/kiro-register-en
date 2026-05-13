"""Abstract base class for mail-provider implementations."""
from abc import ABC, abstractmethod


class MailProvider(ABC):
    """Base class every mail provider must implement."""

    name: str = "base"
    display_name: str = "Base Provider"

    @abstractmethod
    def create_mailbox(self) -> str:
        """Create a temporary mailbox and return the email address."""
        ...

    @abstractmethod
    def wait_otp(self, timeout: int = 120, poll_interval: int = 3) -> str:
        """Poll for an OTP code; return the 6-digit code or an empty string on timeout."""
        ...

    @abstractmethod
    def list_domains(self) -> list[dict]:
        """
        Return the available domains for this provider.

        Return shape: [{"id": "...", "domain": "..."}, ...]
        """
        ...
