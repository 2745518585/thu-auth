import requests

from .config import load_config

session = None

class SessionWithTimeout(requests.Session):
    def __init__(self):
        super().__init__()

    def request(self, *args, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = load_config()["config"]["requests_timeout"]
        return super().request(*args, **kwargs)

def get_session():
    global session
    if session is None:
        session = SessionWithTimeout()
    return session
