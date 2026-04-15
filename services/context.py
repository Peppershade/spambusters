"""
User context management for multi-tenant operations.
Provides a way to track the current user across request handling.
"""
from dataclasses import dataclass
from typing import Optional
from contextvars import ContextVar


@dataclass
class UserContext:
    """Represents the current user's context for multi-tenant operations."""
    user_id: int
    username: str
    is_admin: bool
    session_id: Optional[str] = None

    @property
    def model_dir(self) -> str:
        """Directory for user's ML model files."""
        return f"models/{self.user_id}"

    @property
    def model_path(self) -> str:
        """Path to user's spam model."""
        return f"models/{self.user_id}/spam_model.pt"

    @property
    def vectorizer_path(self) -> str:
        """Path to user's vectorizer."""
        return f"models/{self.user_id}/vectorizer.pkl"


# Context variable for current user (thread-safe)
_current_user: ContextVar[Optional[UserContext]] = ContextVar('current_user', default=None)


def get_current_user() -> Optional[UserContext]:
    """Get the current user context."""
    return _current_user.get()


def set_current_user(user: UserContext):
    """Set the current user context."""
    _current_user.set(user)


def clear_current_user():
    """Clear the current user context."""
    _current_user.set(None)


def require_user_context() -> UserContext:
    """
    Get the current user context, raising an error if not set.
    Use this in functions that require a user context.
    """
    user = get_current_user()
    if user is None:
        raise RuntimeError("No user context available. Ensure user is authenticated.")
    return user
