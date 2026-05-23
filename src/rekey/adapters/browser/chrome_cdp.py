"""Chrome CDP browser session adapter.

Connects to a running Chrome process via the DevTools Protocol so the agent
operates in the user's REAL browser profile — preserving existing logins
and cookies. Most in-session password changes then skip CAPTCHA entirely.

Usage on macOS::

    /Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome \\
        --remote-debugging-port=9222
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CDPConfig:
    """Where to connect to a running Chrome."""

    host: str = "127.0.0.1"
    port: int = 9222

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


class ChromeCDPSession:
    """Lifecycle wrapper around a browser-use Browser attached to running Chrome."""

    def __init__(self, config: CDPConfig | None = None) -> None:
        self._config = config or CDPConfig()
        self._browser: Any | None = None

    async def open(self) -> Any:
        """Connect to Chrome and return the browser-use Browser instance."""
        if self._browser is None:
            from browser_use import Browser

            self._browser = Browser(cdp_url=self._config.url)
        return self._browser

    async def close(self) -> None:
        """Detach from Chrome — does NOT close the user's browser."""
        if self._browser is None:
            return
        try:
            await self._browser.close()
        except Exception as e:  # noqa: BLE001 — detach is best-effort
            logger.debug("Browser close raised: %s", e)
        finally:
            self._browser = None

    @property
    def config(self) -> CDPConfig:
        return self._config
