"""Shared business services used by the REST API, the web app and MCP tools.

The service layer owns validation, account-scoped record access and the
projection pipeline so every external access path applies the same rules:

- ``access``      — effective-user (tenant) resolution and write permission
- ``validation``  — field parsing/validation shared by REST and MCP
- ``projections`` — the persistent projection pipeline (``update_cash`` with
  ``commit=True``) plus read-only analysis helpers
- ``records``     — ownership-scoped CRUD for schedules, scenarios, holds, skips

Services raise :class:`app.services.errors.ServiceError` subclasses; callers map
them to their own transport (REST JSON envelope, MCP tool error, flash message).
Services never trust caller-supplied user or owner identifiers: every function
takes the *effective user id* that the caller derived from its authenticated
principal.
"""
