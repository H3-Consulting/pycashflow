"""
DATABASE_URL handling in the app factory.

Regression coverage for the 4.5.8 outage: SQLAlchemy 2.1 made psycopg 3 the
default driver for driverless ``postgresql://`` URLs, but the image ships
psycopg2, so the app crashed on start-up against PostgreSQL.
"""

import importlib

import pytest


@pytest.fixture(scope="module")
def normalize():
    return importlib.import_module("app").normalize_database_url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("postgresql://u:p@db.example.com:25060/pycashflow?sslmode=require",
         "postgresql+psycopg2://u:p@db.example.com:25060/pycashflow?sslmode=require"),
        ("postgres://u:p@host/db", "postgresql+psycopg2://u:p@host/db"),
        # An explicitly chosen driver is respected.
        ("postgresql+psycopg2://u:p@host/db", "postgresql+psycopg2://u:p@host/db"),
        ("postgresql+psycopg://u:p@host/db", "postgresql+psycopg://u:p@host/db"),
        # Non-PostgreSQL URLs pass through untouched.
        ("sqlite:////app/app/data/db.sqlite", "sqlite:////app/app/data/db.sqlite"),
        ("sqlite:///:memory:", "sqlite:///:memory:"),
        ("", ""),
        (None, None),
    ],
)
def test_normalize_database_url(normalize, url, expected):
    assert normalize(url) == expected


def test_create_app_uses_psycopg2_for_plain_postgresql_url(create_app, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost:5432/pycashflow")
    app = create_app()
    assert app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql+psycopg2://")
    with app.app_context():
        # Building the engine imports the DBAPI, which is what crashed in 4.5.8.
        engine = app.extensions["sqlalchemy"].engine
        assert engine.dialect.driver == "psycopg2"
