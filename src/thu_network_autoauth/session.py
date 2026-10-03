import requests
import time

from .config import load_config

session = None


class SessionWithTimeout(requests.Session):
    def __init__(self):
        super().__init__()

    def request(self, *args, **kwargs) -> requests.Response:
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = load_config()["config"]["requests_timeout"]
        method = kwargs.get("method", args[0] if args else "").upper()
        # Only replay reads. A failed POST may already have reached the server.
        attempts = 3 if method in {"GET", "HEAD"} else 1
        for attempt in range(attempts):
            try:
                response = super().request(*args, **kwargs)
                if (
                    response.status_code not in {429, 502, 503, 504}
                    or attempt == attempts - 1
                ):
                    return response
                response.close()
            except requests.RequestException:
                if attempt == attempts - 1:
                    raise
            time.sleep(0.5 * (2**attempt))

        raise RuntimeError("Request retry attempts exhausted")


def get_session():
    global session
    if session is None:
        session = SessionWithTimeout()
    return session


def reset_session():
    """Discard cookies and pooled connections after a failed monitoring cycle."""
    global session
    previous, session = session, None
    if previous is not None:
        previous.close()
