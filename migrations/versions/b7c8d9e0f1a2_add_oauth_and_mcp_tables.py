"""add OAuth authorization server and MCP tables

Additive only: creates the tables backing the OAuth 2.1 authorization server
used by MCP clients (ChatGPT, Claude) — registered clients, authorization
codes, grants (connected applications), tokens, an audit trail and MCP
idempotency keys. No existing table is modified. The tables are unused while
MCP_ENABLED=false.

Revision ID: b7c8d9e0f1a2
Revises: f8b1c2d3e4a5
Create Date: 2026-11-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b7c8d9e0f1a2'
down_revision = 'f8b1c2d3e4a5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'oauth_clients',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.String(length=512), nullable=False),
        sa.Column('registration_type', sa.String(length=10), nullable=False),
        sa.Column('client_secret_hash', sa.String(length=64), nullable=True),
        sa.Column('client_name', sa.String(length=200), nullable=True),
        sa.Column('client_uri', sa.String(length=512), nullable=True),
        sa.Column('redirect_uris', sa.Text(), nullable=False),
        sa.Column('grant_types', sa.Text(), nullable=False),
        sa.Column('response_types', sa.Text(), nullable=False),
        sa.Column('scope', sa.String(length=500), nullable=True),
        sa.Column('token_endpoint_auth_method', sa.String(length=40), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('metadata_fetched_at', sa.DateTime(), nullable=True),
        sa.Column('metadata_expires_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('oauth_clients', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_oauth_clients_client_id'), ['client_id'], unique=True)

    op.create_table(
        'oauth_grants',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.String(length=512), nullable=False),
        sa.Column('client_name', sa.String(length=200), nullable=True),
        sa.Column('scope', sa.String(length=500), nullable=False),
        sa.Column('resource', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_reason', sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('oauth_grants', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_oauth_grants_client_id'), ['client_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_oauth_grants_user_id'), ['user_id'], unique=False)

    op.create_table(
        'oauth_authorization_codes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('code_hash', sa.String(length=64), nullable=False),
        sa.Column('client_id', sa.String(length=512), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('redirect_uri', sa.String(length=1024), nullable=False),
        sa.Column('scope', sa.String(length=500), nullable=False),
        sa.Column('resource', sa.String(length=512), nullable=False),
        sa.Column('code_challenge', sa.String(length=128), nullable=False),
        sa.Column('code_challenge_method', sa.String(length=10), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('grant_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['grant_id'], ['oauth_grants.id']),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('oauth_authorization_codes', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_oauth_authorization_codes_code_hash'), ['code_hash'], unique=True
        )
        batch_op.create_index(
            batch_op.f('ix_oauth_authorization_codes_user_id'), ['user_id'], unique=False
        )

    op.create_table(
        'oauth_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('grant_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.String(length=512), nullable=False),
        sa.Column('scope', sa.String(length=500), nullable=False),
        sa.Column('resource', sa.String(length=512), nullable=False),
        sa.Column('access_token_hash', sa.String(length=64), nullable=False),
        sa.Column('refresh_token_hash', sa.String(length=64), nullable=True),
        sa.Column('issued_at', sa.DateTime(), nullable=False),
        sa.Column('access_expires_at', sa.DateTime(), nullable=False),
        sa.Column('refresh_expires_at', sa.DateTime(), nullable=True),
        sa.Column('access_revoked_at', sa.DateTime(), nullable=True),
        sa.Column('refresh_revoked_at', sa.DateTime(), nullable=True),
        sa.Column('refresh_revoked_reason', sa.String(length=40), nullable=True),
        sa.ForeignKeyConstraint(['grant_id'], ['oauth_grants.id']),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('oauth_tokens', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_oauth_tokens_access_token_hash'), ['access_token_hash'], unique=True
        )
        batch_op.create_index(batch_op.f('ix_oauth_tokens_grant_id'), ['grant_id'], unique=False)
        batch_op.create_index(
            batch_op.f('ix_oauth_tokens_refresh_token_hash'), ['refresh_token_hash'], unique=True
        )
        batch_op.create_index(batch_op.f('ix_oauth_tokens_user_id'), ['user_id'], unique=False)

    op.create_table(
        'oauth_audit_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('client_id', sa.String(length=512), nullable=True),
        sa.Column('grant_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=32), nullable=True),
        sa.Column('resource_id', sa.String(length=64), nullable=True),
        sa.Column('outcome', sa.String(length=16), nullable=False),
        sa.Column('error_code', sa.String(length=40), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('oauth_audit_events', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_oauth_audit_events_created_at'), ['created_at'], unique=False
        )
        batch_op.create_index(batch_op.f('ix_oauth_audit_events_user_id'), ['user_id'], unique=False)

    op.create_table(
        'mcp_idempotency_keys',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.String(length=512), nullable=False),
        sa.Column('idempotency_key', sa.String(length=128), nullable=False),
        sa.Column('tool_name', sa.String(length=64), nullable=False),
        sa.Column('request_hash', sa.String(length=64), nullable=False),
        sa.Column('response_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'client_id', 'idempotency_key', name='uq_mcp_idempotency_scope'),
    )
    with op.batch_alter_table('mcp_idempotency_keys', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_mcp_idempotency_keys_user_id'), ['user_id'], unique=False
        )


def downgrade():
    with op.batch_alter_table('mcp_idempotency_keys', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mcp_idempotency_keys_user_id'))
    op.drop_table('mcp_idempotency_keys')

    with op.batch_alter_table('oauth_audit_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth_audit_events_user_id'))
        batch_op.drop_index(batch_op.f('ix_oauth_audit_events_created_at'))
    op.drop_table('oauth_audit_events')

    with op.batch_alter_table('oauth_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_oauth_tokens_refresh_token_hash'))
        batch_op.drop_index(batch_op.f('ix_oauth_tokens_grant_id'))
        batch_op.drop_index(batch_op.f('ix_oauth_tokens_access_token_hash'))
    op.drop_table('oauth_tokens')

    with op.batch_alter_table('oauth_authorization_codes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth_authorization_codes_user_id'))
        batch_op.drop_index(batch_op.f('ix_oauth_authorization_codes_code_hash'))
    op.drop_table('oauth_authorization_codes')

    with op.batch_alter_table('oauth_grants', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth_grants_user_id'))
        batch_op.drop_index(batch_op.f('ix_oauth_grants_client_id'))
    op.drop_table('oauth_grants')

    with op.batch_alter_table('oauth_clients', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_oauth_clients_client_id'))
    op.drop_table('oauth_clients')
