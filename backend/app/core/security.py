from typing import Any, Optional
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer(auto_error=False)


class CurrentUser(dict):
    def __getattr__(self, name: str) -> Any:
        return self.get(name)


User = CurrentUser

DEFAULT_USER = CurrentUser(
    sub="00000000-0000-0000-0000-000000000001",
    id="00000000-0000-0000-0000-000000000001",
    username="admin",
    preferred_username="admin",
    email="admin@local",
    full_name="Local Admin",
    roles=["admin", "specialist", "analyst", "secops_admin", "user"],
    realm_access={
        "roles": ["admin", "specialist", "analyst", "secops_admin", "user"]
    },
)


def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> CurrentUser:
    return DEFAULT_USER


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> CurrentUser:
    return DEFAULT_USER


def require_role(*args: Any, **kwargs: Any):
    def _checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        return user

    return _checker


require_roles = require_role


class RoleChecker:
    def __init__(self, *args: Any, **kwargs: Any):
        pass

    def __call__(self, user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        return user
