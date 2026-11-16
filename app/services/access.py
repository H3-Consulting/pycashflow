"""Tenant resolution and write-permission rules shared by all access paths."""

from __future__ import annotations


def effective_user_id(user) -> int:
    """Return the account (data owner) id a user operates on.

    Guests read their account owner's data; owners read their own. This mirrors
    ``main.get_effective_user_id`` and ``api/routes/data._effective_user_id``.
    """
    return user.owner_user_id or user.account_owner_id or user.id


def is_guest(user) -> bool:
    """Return True for guest (view-only) users linked to an account owner."""
    return (user.owner_user_id is not None) or (user.account_owner_id is not None)


def can_write_financial_data(user) -> bool:
    """Return True when *user* may modify schedules, scenarios, holds or skips.

    The REST API and web app gate writes on ``user.admin`` (guests are created
    with ``admin=False``). New external paths additionally refuse anyone linked
    to an owner, so a mis-flagged guest can never write the owner's data.
    """
    return bool(user.admin) and not is_guest(user)
