"""ShiroMail temporary-mailbox provider."""
import re
import time

from .base import MailProvider


class ShiroMailProvider(MailProvider):

    name = "shiromail"
    display_name = "ShiroMail"

    def __init__(self, base_url: str = "", api_key: str = "", domain_id=None):
        from curl_cffi import requests as curl_requests
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        if domain_id and str(domain_id).isdigit():
            self.domain_id = int(domain_id)
        else:
            self.domain_id = 0
        self.session = curl_requests.Session(impersonate="chrome131")
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.mailbox_id = None
        self.address = None

    def create_mailbox(self) -> str:
        resp = self.session.post(
            f"{self.base_url}/api/v1/mailboxes",
            headers=self.headers,
            json={"domainId": self.domain_id, "expiresInHours": 3},
            timeout=15, verify=False,
        )
        data = resp.json()
        self.mailbox_id = data["id"]
        self.address = data["address"]
        return self.address

    def wait_otp(self, timeout: int = 120, poll_interval: int = 3) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.session.get(
                f"{self.base_url}/api/v1/mailboxes/{self.mailbox_id}/messages",
                headers=self.headers, timeout=10, verify=False,
            )
            if resp.status_code == 200:
                messages = resp.json()
                items = messages.get("items", []) if isinstance(messages, dict) else messages
                if items:
                    msg_id = items[0]["id"]
                    ext_resp = self.session.get(
                        f"{self.base_url}/api/v1/mailboxes/{self.mailbox_id}/messages/{msg_id}/extractions",
                        headers=self.headers, timeout=10, verify=False,
                    )
                    if ext_resp.status_code == 200:
                        extractions = ext_resp.json()
                        ext_items = extractions.get("items", extractions) if isinstance(extractions, dict) else extractions
                        if isinstance(ext_items, list):
                            for ext in ext_items:
                                val = ext.get("value", "")
                                if re.match(r'^\d{6}$', val):
                                    return val
                    detail_resp = self.session.get(
                        f"{self.base_url}/api/v1/mailboxes/{self.mailbox_id}/messages/{msg_id}",
                        headers=self.headers, timeout=10, verify=False,
                    )
                    if detail_resp.status_code == 200:
                        detail = detail_resp.json()
                        body = detail.get("body", "") or detail.get("textBody", "") or detail.get("htmlBody", "") or str(detail)
                        match = re.search(r'\b(\d{6})\b', body)
                        if match:
                            return match.group(1)
            time.sleep(poll_interval)
        return ""

    def list_domains(self) -> list[dict]:
        resp = self.session.get(
            f"{self.base_url}/api/v1/domains",
            headers=self.headers, timeout=10, verify=False,
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            if isinstance(items, list):
                return [
                    {"id": str(d.get("id", "")), "domain": d.get("domain", d.get("name", ""))}
                    for d in items if d.get("id")
                ]
        return []
