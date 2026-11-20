from flask_login import UserMixin
from app import db
from datetime import datetime, timezone


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100))
    password = db.Column(db.String(256))  # Scrypt passwords are ~150 chars
    name = db.Column(db.String(1000))
    admin = db.Column(db.Boolean)
    is_global_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    account_owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_account_owner = db.Column(db.Boolean, default=True, nullable=False, server_default=db.true())
    owner_user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', name='fk_user_owner_user_id'), nullable=True
    )
    twofa_enabled = db.Column(db.Boolean, default=False, server_default=db.false(), nullable=False)
    twofa_secret = db.Column(db.String(500), nullable=True)   # Fernet-encrypted TOTP secret
    twofa_backup_codes = db.Column(db.Text, nullable=True)    # JSON array of scrypt-hashed backup codes
    # Marks an account owner as an Apple/store reviewer test account. Reviewer
    # accounts bypass payment-subscription enforcement and remain active.
    is_review_user = db.Column(
        db.Boolean, default=False, server_default=db.false(), nullable=False
    )
    # Last consumed Plaid /accounts/balance/get cooldown slot for this user.
    # Persisted on the user (not just the PlaidConnection) so deleting and
    # re-adding the Plaid account does not reset the 24-hour rate limit.
    last_plaid_realtime_balance_at = db.Column(db.DateTime, nullable=True)
    # When PyCashFlow last accepted a manual balance entry for this user
    # (web form or iOS API). Stored as naive UTC. The Plaid cached
    # /accounts/get sync compares this against Plaid's cached freshness so a
    # stale cached balance cannot overwrite a newer manually-entered value.
    last_manual_balance_entry_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    guests = db.relationship(
        'User',
        foreign_keys='User.account_owner_id',
        backref=db.backref('account_owner', remote_side=[id]),
    )
    subscriptions = db.relationship(
        'Subscription',
        back_populates='user',
        cascade='all, delete-orphan',
        lazy='dynamic',
    )

    @property
    def active_subscription(self):
        """Return the most recent currently-active subscription, if any."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return (
            self.subscriptions.filter(
                Subscription.status.in_(["active", "trial", "grace_period"]),
                db.or_(Subscription.expires_at.is_(None), Subscription.expires_at >= now),
            )
            .order_by(Subscription.updated_at.desc(), Subscription.id.desc())
            .first()
        )

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('email', name='uq_user_email'),
    )


class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Numeric(10, 2))
    frequency = db.Column(db.String(100))
    startdate = db.Column(db.Date)
    type = db.Column(db.String(100))
    firstdate = db.Column(db.Date)

    # Relationships
    user = db.relationship('User', backref='schedules')

    # Unique constraint per user
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='_user_schedule_uc'),)


class Scenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Numeric(10, 2))
    frequency = db.Column(db.String(100))
    startdate = db.Column(db.Date)
    type = db.Column(db.String(100))
    firstdate = db.Column(db.Date)

    # Relationships
    user = db.relationship('User', backref='scenarios')

    # Unique constraint per user
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='_user_scenario_uc'),)


class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    amount = db.Column(db.Numeric(10, 2))
    date = db.Column(db.Date)

    # Relationships
    user = db.relationship('User', backref='balances')

    __table_args__ = (
        db.Index('ix_balance_user_id_date_id', 'user_id', 'date', 'id'),
        db.UniqueConstraint('user_id', 'date', name='uq_balance_user_id_date'),
    )


class Hold(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    amount = db.Column(db.Numeric(10, 2))
    name = db.Column(db.String(100))
    type = db.Column(db.String(100))

    # Relationships
    user = db.relationship('User', backref='holds')


class Skip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(100))
    date = db.Column(db.Date)
    amount = db.Column(db.Numeric(10, 2))
    type = db.Column(db.String(100))

    # Relationships
    user = db.relationship('User', backref='skips')


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    value = db.Column(db.Boolean)

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('name', name='uq_settings_name'),
    )


class TextSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    value = db.Column(db.String(500))

    # Constraints
    __table_args__ = (
        db.UniqueConstraint('name', name='uq_text_settings_name'),
    )


class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(500))
    server = db.Column(db.String(100))
    subjectstr = db.Column(db.String(100))
    startstr = db.Column(db.String(100))
    endstr = db.Column(db.String(100))
    # Expected sender address or domain for inbound balance emails.
    # Exact match: 'alerts@bank.com'  Domain match: '@bank.com'
    # NULL means no restriction is configured (ingestion proceeds with a warning).
    allowed_sender = db.Column(db.String(200), nullable=True)
    # Timestamp of the most recent balance email this config produced. Stored
    # as naive UTC (Date header → UTC; processing time fallback). The Plaid
    # cached /accounts/get sync compares this against Plaid's cached freshness
    # so a stale cached balance cannot overwrite a newer email-derived one.
    balance_email_datetime = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship('User', backref='email_configs')


class GlobalEmailSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    smtp_server = db.Column(db.String(100), nullable=False)

    # Constraints - only one global email settings record allowed
    __table_args__ = (
        db.CheckConstraint('id = 1', name='single_row_check'),
    )


class AISettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    api_key = db.Column(db.String(500), nullable=True)  # Fernet-encrypted OpenAI API key
    model_version = db.Column(db.String(100), nullable=True)  # OpenAI model to use (e.g. gpt-4o-mini)
    last_updated = db.Column(db.DateTime, nullable=True)
    last_insights = db.Column(db.Text, nullable=True)  # JSON string of cached insights

    # Relationships
    user = db.relationship('User', backref='ai_settings')

    # One settings record per user
    __table_args__ = (
        db.UniqueConstraint('user_id', name='_ai_settings_user_uc'),
    )


class PasskeyCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    credential_id = db.Column(db.String(512), nullable=False, unique=True, index=True)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    transports = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime, nullable=True)
    label = db.Column(db.String(120), nullable=True)

    # Relationships
    user = db.relationship('User', backref='passkey_credentials')


class UserToken(db.Model):
    """Opaque bearer tokens for stateless API authentication.

    The raw token is returned to the client exactly once (at creation).
    Only its SHA-256 hash is stored server-side, so a database breach cannot
    be used to impersonate users directly.
    """
    __tablename__ = 'user_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    # SHA-256 hex digest of the raw token
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)

    # Relationships
    user = db.relationship('User', backref='api_tokens')


class PasswordSetupToken(db.Model):
    """One-time password setup tokens used for payment-created users."""

    __tablename__ = 'password_setup_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship('User', backref='password_setup_tokens')


class PlaidConnection(db.Model):
    """Minimal Plaid Item/account metadata for the Balance integration.

    Stores only the connection info needed to call /accounts/balance/get for
    a single depository account per user. The encrypted access token is the
    only sensitive field; queried balances and raw Plaid payloads are never
    persisted here.
    """

    __tablename__ = 'plaid_connections'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    encrypted_access_token = db.Column(db.Text, nullable=False)
    plaid_item_id = db.Column(db.String(255), nullable=False)
    plaid_account_id = db.Column(db.String(255), nullable=False)
    institution_id = db.Column(db.String(100), nullable=True)
    institution_name = db.Column(db.String(255), nullable=True)
    account_name = db.Column(db.String(255), nullable=True)
    account_mask = db.Column(db.String(10), nullable=True)
    account_type = db.Column(db.String(50), nullable=True)
    account_subtype = db.Column(db.String(50), nullable=True)
    iso_currency_code = db.Column(db.String(10), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    last_balance_sync_at = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(64), nullable=True)
    last_sync_error = db.Column(db.String(255), nullable=True)
    # Last attempted /accounts/balance/get call. Used to rate-limit the
    # paid real-time refresh to once every 24 hours per user/connection.
    # Set BEFORE calling Plaid so a failed-but-billed call still consumes
    # the cooldown window and rapid double-clicks cannot duplicate paid
    # calls.
    last_realtime_balance_at = db.Column(db.DateTime, nullable=True)
    # Dedicated status/error columns for the real-time refresh so a Plaid
    # /accounts/balance/get failure does not overwrite the unrelated status
    # of the automatic /accounts/get sync (last_sync_status/last_sync_error).
    last_realtime_refresh_status = db.Column(db.String(64), nullable=True)
    last_realtime_refresh_error = db.Column(db.String(255), nullable=True)
    # When the bank consent behind this Item ends (naive UTC), as reported by
    # Plaid's /item/get ``item.consent_expiration_time``. Null means no
    # expiration is currently scheduled (or it has not been read yet). Some
    # institutions, e.g. Chase, let consumers pick a 6- or 12-month limit.
    consent_expiration_time = db.Column(db.DateTime, nullable=True)
    # Set (naive UTC) when Plaid reports an Item error only the user can fix
    # by going back through Plaid Link (expired or revoked consent, changed
    # credentials). Cleared by the next successful /accounts/get sync.
    reconnect_required_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    user = db.relationship('User', backref='plaid_connections')

    __table_args__ = (
        # Only one active Plaid connection per user.
        db.Index(
            'uq_plaid_connection_active_user',
            'user_id',
            unique=True,
            sqlite_where=db.text('is_active = 1'),
            postgresql_where=db.text('is_active'),
        ),
    )


class Subscription(db.Model):
    """Normalized provider subscription state tied to account owner users."""

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    source = db.Column(db.String(20), nullable=False)
    environment = db.Column(db.String(20), nullable=True)
    product_id = db.Column(db.String(255), nullable=True)
    original_transaction_id = db.Column(db.String(255), nullable=True)
    latest_transaction_id = db.Column(db.String(255), nullable=True)
    external_subscription_id = db.Column(db.String(255), nullable=True)
    status = db.Column(
        db.String(20),
        nullable=False,
        default='inactive',
        server_default='inactive',
    )
    expires_at = db.Column(db.DateTime, nullable=True)
    raw_last_verified_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    user = db.relationship('User', back_populates='subscriptions')

    __table_args__ = (
        db.UniqueConstraint(
            'source',
            'environment',
            'original_transaction_id',
            name='uq_subscription_apple_original',
        ),
        db.UniqueConstraint(
            'source',
            'external_subscription_id',
            name='uq_subscription_external_source_id',
        ),
    )


# ── OAuth 2.1 authorization server / MCP integration ────────────────────────
#
# These tables back the OAuth authorization server used by MCP clients
# (ChatGPT, Claude). They are deliberately separate from ``user_tokens`` so
# OAuth credentials can never be confused with iOS/REST bearer tokens: each
# OAuth token is bound to a client, a grant (one user approval), a resource
# (the MCP endpoint) and an explicit scope set. Only SHA-256 hashes of codes,
# tokens and client secrets are stored.


def _utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class OAuthClient(db.Model):
    """A registered OAuth client (Dynamic Client Registration or CIMD cache)."""

    __tablename__ = 'oauth_clients'

    id = db.Column(db.Integer, primary_key=True)
    # Random id for DCR clients; the HTTPS metadata URL for CIMD clients.
    client_id = db.Column(db.String(512), nullable=False, unique=True, index=True)
    # 'dcr' or 'cimd'
    registration_type = db.Column(db.String(10), nullable=False)
    client_secret_hash = db.Column(db.String(64), nullable=True)
    client_name = db.Column(db.String(200), nullable=True)
    client_uri = db.Column(db.String(512), nullable=True)
    redirect_uris = db.Column(db.Text, nullable=False)  # JSON array
    grant_types = db.Column(db.Text, nullable=False)  # JSON array
    response_types = db.Column(db.Text, nullable=False)  # JSON array
    scope = db.Column(db.String(500), nullable=True)
    token_endpoint_auth_method = db.Column(db.String(40), nullable=False, default='none')
    is_active = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive)
    updated_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive, onupdate=_utcnow_naive)
    # CIMD cache bookkeeping
    metadata_fetched_at = db.Column(db.DateTime, nullable=True)
    metadata_expires_at = db.Column(db.DateTime, nullable=True)


class OAuthAuthorizationCode(db.Model):
    """Short-lived, single-use authorization code (PKCE-bound)."""

    __tablename__ = 'oauth_authorization_codes'

    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    client_id = db.Column(db.String(512), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    redirect_uri = db.Column(db.String(1024), nullable=False)
    scope = db.Column(db.String(500), nullable=False)
    resource = db.Column(db.String(512), nullable=False)
    code_challenge = db.Column(db.String(128), nullable=False)
    code_challenge_method = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive)
    expires_at = db.Column(db.DateTime, nullable=False)
    # Set atomically when the code is redeemed; a second redemption is a
    # replay and revokes the grant created by the first one.
    used_at = db.Column(db.DateTime, nullable=True)
    grant_id = db.Column(db.Integer, db.ForeignKey('oauth_grants.id'), nullable=True)


class OAuthGrant(db.Model):
    """One user approval of one client: a connected application.

    All access/refresh tokens issued from the same authorization belong to
    the grant, so revoking the grant (from the connected-apps page, by
    refresh-token replay detection or by a password change) revokes the
    whole token family without touching other clients or iOS sessions.
    """

    __tablename__ = 'oauth_grants'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    client_id = db.Column(db.String(512), nullable=False, index=True)
    client_name = db.Column(db.String(200), nullable=True)
    scope = db.Column(db.String(500), nullable=False)
    resource = db.Column(db.String(512), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive)
    last_used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(40), nullable=True)


class OAuthToken(db.Model):
    """An access token and (optionally) its paired refresh token."""

    __tablename__ = 'oauth_tokens'

    id = db.Column(db.Integer, primary_key=True)
    grant_id = db.Column(db.Integer, db.ForeignKey('oauth_grants.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    client_id = db.Column(db.String(512), nullable=False)
    scope = db.Column(db.String(500), nullable=False)
    resource = db.Column(db.String(512), nullable=False)
    access_token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    refresh_token_hash = db.Column(db.String(64), nullable=True, unique=True, index=True)
    issued_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive)
    access_expires_at = db.Column(db.DateTime, nullable=False)
    refresh_expires_at = db.Column(db.DateTime, nullable=True)
    access_revoked_at = db.Column(db.DateTime, nullable=True)
    refresh_revoked_at = db.Column(db.DateTime, nullable=True)
    # 'rotated' (normal refresh), 'revoked', 'replay', 'grant_revoked'
    refresh_revoked_reason = db.Column(db.String(40), nullable=True)


class OAuthAuditEvent(db.Model):
    """Audit trail of OAuth grant lifecycle events and MCP mutations.

    Stores identifiers and outcomes only — never tokens, secrets, names or
    amounts — to keep financial data out of the audit store.
    """

    __tablename__ = 'oauth_audit_events'

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    client_id = db.Column(db.String(512), nullable=True)
    grant_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(32), nullable=True)
    resource_id = db.Column(db.String(64), nullable=True)
    outcome = db.Column(db.String(16), nullable=False)
    error_code = db.Column(db.String(40), nullable=True)
    correlation_id = db.Column(db.String(64), nullable=True)


class McpIdempotencyKey(db.Model):
    """Replay protection for MCP write tools keyed by a client-chosen key."""

    __tablename__ = 'mcp_idempotency_keys'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    client_id = db.Column(db.String(512), nullable=False)
    idempotency_key = db.Column(db.String(128), nullable=False)
    tool_name = db.Column(db.String(64), nullable=False)
    request_hash = db.Column(db.String(64), nullable=False)
    response_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow_naive)

    __table_args__ = (
        db.UniqueConstraint(
            'user_id', 'client_id', 'idempotency_key', name='uq_mcp_idempotency_scope'
        ),
    )
