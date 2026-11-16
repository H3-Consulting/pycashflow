"""API v1 data endpoints for mobile clients (read + write)."""

from datetime import datetime, timedelta, timezone
import json

from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError

from flask import request, g

from app import db
from app.models import Schedule, Scenario, Balance, Hold, Skip, AISettings
from app.cashflow import update_cash, calculate_cash_risk_score
from app.services import access as access_service
from app.services import projections as projection_service
from app.services.records import apply_start_date
from app.services.validation import (
    MAX_NAME_LEN,
    VALID_FREQUENCIES,
    VALID_TYPES,
    validate_balance_amount,
    validate_item_payload,
)
from app.ai_insights import (
    AIProviderError,
    AIInsightsFormatError,
    fetch_insights_for_provider,
    is_refresh_due,
    normalize_and_validate_insights_json,
    select_provider,
)
from app.files import version
from app.plaid_service import (
    safe_update_plaid_balance_for_user,
    record_manual_balance_entry,
)
from app.models import User

from app.api import api
from app.api.auth_utils import api_login_required, get_api_user
from app.api.errors import validation_error, not_found, forbidden
from app.api.responses import api_ok, api_list, api_created, api_no_content
from app.api.serializers import (
    serialize_schedule,
    serialize_scenario,
    serialize_balance,
    serialize_hold,
    serialize_skip,
    _amount,
    _date,
    _datetime,
)


_VALID_TYPES = set(VALID_TYPES)
_VALID_FREQUENCIES = set(VALID_FREQUENCIES)
_MAX_NAME_LEN = MAX_NAME_LEN


def _effective_user_id() -> int:
    # Guest isolation: every data query filters by this id. The rule lives in
    # app.services.access so the MCP integration applies the identical rule.
    return access_service.effective_user_id(get_api_user())


def _balance_owner_user():
    """Return the user object whose balance is the source of truth."""
    user = get_api_user()
    effective_id = _effective_user_id()
    if effective_id == user.id:
        return user
    return User.query.get(effective_id)


def _forbid_guest_writes():
    user = get_api_user()
    if not user.admin:
        return forbidden("Guest users are read-only")
    return None


def _latest_balance(user_id: int):
    return projection_service.latest_balance(user_id)


def _parse_limit_offset():
    limit_raw = request.args.get("limit")
    offset_raw = request.args.get("offset")
    if limit_raw is None and offset_raw is None:
        return None, None, None

    errors = {}
    try:
        limit = int(limit_raw) if limit_raw is not None else 50
        if limit <= 0:
            raise ValueError
    except (TypeError, ValueError):
        errors["limit"] = "limit must be a positive integer"
        limit = None

    try:
        offset = int(offset_raw) if offset_raw is not None else 0
        if offset < 0:
            raise ValueError
    except (TypeError, ValueError):
        errors["offset"] = "offset must be an integer >= 0"
        offset = None

    if errors:
        return errors, None, None
    return None, limit, offset


def _validate_schedule_payload(body: dict) -> dict:
    # Shared with the MCP integration; messages are unchanged for REST clients.
    return validate_item_payload(body)


def _validate_balance_payload(body: dict) -> dict:
    errors = {}
    amount_error = validate_balance_amount(body.get("amount"))
    if amount_error:
        errors["amount"] = amount_error

    date_val = body.get("date")
    if date_val:
        try:
            datetime.strptime(date_val, "%Y-%m-%d")
        except (TypeError, ValueError):
            errors["date"] = "date must be YYYY-MM-DD"
    return errors


def _project_data(user_id: int):
    cache = getattr(g, "_project_data_cache", None)
    if cache is None:
        cache = {}
        g._project_data_cache = cache
    if user_id in cache:
        return cache[user_id]

    # Persistent projection pipeline: update_cash(..., commit=True) on the
    # account's own rows (see app.services.projections.run_projection).
    projection = projection_service.run_projection(user_id)
    result = (
        projection.balance,
        projection.balance_amount,
        projection.trans,
        projection.run,
        projection.run_scenario,
    )
    cache[user_id] = result
    return result


@api.route("/dashboard", methods=["GET"])
@api_login_required
def api_dashboard():
    user_id = _effective_user_id()
    # Refresh today's balance from Plaid before computing projections. Never
    # raises — Plaid errors or missing config leave existing data intact.
    safe_update_plaid_balance_for_user(_balance_owner_user())
    balance, balance_amount, trans, run, _run_scenario = _project_data(user_id)

    cash_risk = calculate_cash_risk_score(balance_amount, run)
    risk_v2 = {
        "score": cash_risk["score"],
        "status": cash_risk["status"],
        "color": cash_risk["color"],
        "runway_days": cash_risk["runway_days"],
        "lowest_balance": _amount(cash_risk["lowest_balance"]),
        "days_to_lowest": cash_risk["days_to_lowest"],
        "avg_daily_expense": _amount(cash_risk["avg_daily_expense"]),
        "days_below_threshold": cash_risk["days_below_threshold"],
        "pct_below_threshold": cash_risk["pct_below_threshold"],
        "recovery_days": cash_risk["recovery_days"],
        "near_term_buffer": _amount(cash_risk["near_term_buffer"]),
    }

    todaydate = datetime.today().date()
    horizon_90 = todaydate + timedelta(days=90)
    if not run.empty:
        run_copy = run.copy()
        run_copy["amount"] = run_copy["amount"].astype(float)
        run_90 = run_copy[run_copy["date"] <= horizon_90]
        min_balance = float(run_90["amount"].min()) if not run_90.empty else float(run_copy["amount"].min())
    else:
        min_balance = balance_amount

    upcoming = []
    if not trans.empty:
        for row in trans.itertuples(index=False):
            upcoming.append({"name": row.name, "type": row.type, "amount": _amount(row.amount), "date": _date(row.date)})

    ai_config = AISettings.query.filter_by(user_id=user_id).first()
    ai_insights = None
    ai_last_updated = None
    if ai_config and ai_config.last_insights:
        try:
            ai_insights = json.loads(ai_config.last_insights)
            ai_last_updated = _datetime(ai_config.last_updated)
        except (json.JSONDecodeError, ValueError, TypeError):
            ai_insights = None

    balance_date = balance.date if balance else todaydate
    return api_ok({
        "balance": _amount(balance_amount),
        "balance_date": _date(balance_date),
        "risk": cash_risk,
        "risk_deprecated": True,
        "risk_v2": risk_v2,
        "upcoming_transactions": upcoming,
        "min_balance": _amount(min_balance),
        "ai_insights": ai_insights,
        "ai_last_updated": ai_last_updated,
    })


@api.route("/schedules", methods=["GET"])
@api_login_required
def api_schedules():
    user_id = _effective_user_id()
    errors, limit, offset = _parse_limit_offset()
    if errors:
        return validation_error(errors)

    query = Schedule.query.filter_by(user_id=user_id).order_by(Schedule.id.asc())
    if limit is not None:
        total = query.count()
        query = query.limit(limit).offset(offset)
    else:
        total = None

    items = [serialize_schedule(s) for s in query.all()]
    if total is None:
        total = len(items)
    return api_list(items, total=total, limit=limit, offset=offset)


@api.route("/schedules", methods=["POST"])
@api_login_required(require_bearer=True)
def api_create_schedule():
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user_id = _effective_user_id()
    body = request.get_json(silent=True) or {}

    errors = _validate_schedule_payload(body)
    if errors:
        return validation_error(errors)

    name = body["name"].strip()
    if Schedule.query.filter_by(user_id=user_id, name=name).first():
        return validation_error({"name": "Schedule already exists"})

    start = datetime.strptime(body["start_date"], "%Y-%m-%d").date()
    record = Schedule(
        user_id=user_id,
        name=name,
        amount=body["amount"],
        type=body["type"],
        frequency=body["frequency"],
        startdate=start,
        firstdate=start,
    )
    db.session.add(record)
    db.session.commit()
    return api_created(serialize_schedule(record))


@api.route("/schedules/<int:schedule_id>", methods=["PUT"])
@api_login_required(require_bearer=True)
def api_update_schedule(schedule_id: int):
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user_id = _effective_user_id()
    record = Schedule.query.filter_by(user_id=user_id, id=schedule_id).first()
    if not record:
        return not_found("Schedule not found")

    body = request.get_json(silent=True) or {}
    errors = _validate_schedule_payload(body)
    if errors:
        return validation_error(errors)

    new_name = body["name"].strip()
    existing = Schedule.query.filter_by(user_id=user_id, name=new_name).first()
    if existing and existing.id != record.id:
        return validation_error({"name": "Schedule name already exists"})

    start = datetime.strptime(body["start_date"], "%Y-%m-%d").date()
    record.name = new_name
    record.amount = body["amount"]
    record.type = body["type"]
    record.frequency = body["frequency"]
    apply_start_date(record, start)
    db.session.commit()
    return api_ok(serialize_schedule(record))


@api.route("/schedules/<int:schedule_id>", methods=["DELETE"])
@api_login_required(require_bearer=True)
def api_delete_schedule(schedule_id: int):
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user_id = _effective_user_id()
    record = Schedule.query.filter_by(user_id=user_id, id=schedule_id).first()
    if not record:
        return not_found("Schedule not found")
    db.session.delete(record)
    db.session.commit()
    return api_no_content()


@api.route("/projections", methods=["GET"])
@api_login_required
def api_projections():
    user_id = _effective_user_id()
    _balance, _amount_value, _trans, run, run_scenario = _project_data(user_id)

    def _series(df):
        if df is None or df.empty:
            return None
        return [{"date": _date(row.date), "amount": _amount(row.amount)} for row in df.itertuples(index=False)]

    return api_ok({"schedule": _series(run) or [], "scenario": _series(run_scenario)})


@api.route("/scenarios", methods=["GET"])
@api_login_required
def api_scenarios():
    user_id = _effective_user_id()
    errors, limit, offset = _parse_limit_offset()
    if errors:
        return validation_error(errors)

    query = Scenario.query.filter_by(user_id=user_id).order_by(Scenario.id.asc())
    if limit is not None:
        total = query.count()
        query = query.limit(limit).offset(offset)
    else:
        total = None

    items = [serialize_scenario(s) for s in query.all()]
    if total is None:
        total = len(items)
    return api_list(items, total=total, limit=limit, offset=offset)


@api.route("/scenarios", methods=["POST"])
@api_login_required(require_bearer=True)
def api_create_scenario():
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user_id = _effective_user_id()
    body = request.get_json(silent=True) or {}
    errors = _validate_schedule_payload(body)
    if errors:
        return validation_error(errors)

    name = body["name"].strip()
    if Scenario.query.filter_by(user_id=user_id, name=name).first():
        return validation_error({"name": "Scenario already exists"})

    start = datetime.strptime(body["start_date"], "%Y-%m-%d").date()
    record = Scenario(
        user_id=user_id,
        name=name,
        amount=body["amount"],
        type=body["type"],
        frequency=body["frequency"],
        startdate=start,
        firstdate=start,
    )
    db.session.add(record)
    db.session.commit()
    return api_created(serialize_scenario(record))


@api.route("/scenarios/<int:scenario_id>", methods=["PUT"])
@api_login_required(require_bearer=True)
def api_update_scenario(scenario_id: int):
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user_id = _effective_user_id()
    record = Scenario.query.filter_by(user_id=user_id, id=scenario_id).first()
    if not record:
        return not_found("Scenario not found")

    body = request.get_json(silent=True) or {}
    errors = _validate_schedule_payload(body)
    if errors:
        return validation_error(errors)

    new_name = body["name"].strip()
    existing = Scenario.query.filter_by(user_id=user_id, name=new_name).first()
    if existing and existing.id != record.id:
        return validation_error({"name": "Scenario name already exists"})

    start = datetime.strptime(body["start_date"], "%Y-%m-%d").date()
    record.name = new_name
    record.amount = body["amount"]
    record.type = body["type"]
    record.frequency = body["frequency"]
    apply_start_date(record, start)
    db.session.commit()
    return api_ok(serialize_scenario(record))


@api.route("/scenarios/<int:scenario_id>", methods=["DELETE"])
@api_login_required(require_bearer=True)
def api_delete_scenario(scenario_id: int):
    if (resp := _forbid_guest_writes()) is not None:
        return resp
    user_id = _effective_user_id()
    record = Scenario.query.filter_by(user_id=user_id, id=scenario_id).first()
    if not record:
        return not_found("Scenario not found")
    db.session.delete(record)
    db.session.commit()
    return api_no_content()


@api.route("/holds", methods=["GET"])
@api_login_required
def api_holds():
    user_id = _effective_user_id()
    errors, limit, offset = _parse_limit_offset()
    if errors:
        return validation_error(errors)

    query = Hold.query.filter_by(user_id=user_id).order_by(Hold.id.asc())
    if limit is not None:
        total = query.count()
        query = query.limit(limit).offset(offset)
    else:
        total = None

    items = [serialize_hold(h) for h in query.all()]
    if total is None:
        total = len(items)
    return api_list(items, total=total, limit=limit, offset=offset)


@api.route("/holds", methods=["POST"])
@api_login_required(require_bearer=True)
def api_create_hold():
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    body = request.get_json(silent=True) or {}
    schedule_id = body.get("schedule_id")
    if schedule_id is None:
        return validation_error({"schedule_id": "schedule_id is required"})

    schedule = Schedule.query.filter_by(user_id=user_id, id=schedule_id).first()
    if not schedule:
        return not_found("Schedule not found")

    hold = Hold(name=schedule.name, type=schedule.type, amount=schedule.amount, user_id=user_id)
    db.session.add(hold)
    db.session.commit()
    return api_created(serialize_hold(hold))


@api.route("/holds/<int:hold_id>", methods=["DELETE"])
@api_login_required(require_bearer=True)
def api_delete_hold(hold_id: int):
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    hold = Hold.query.filter_by(user_id=user_id, id=hold_id).first()
    if not hold:
        return not_found("Hold not found")
    db.session.delete(hold)
    db.session.commit()
    return api_no_content()


@api.route("/holds", methods=["DELETE"])
@api_login_required(require_bearer=True)
def api_clear_holds():
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    Hold.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return api_no_content()


@api.route("/skips", methods=["GET"])
@api_login_required
def api_skips():
    user_id = _effective_user_id()
    errors, limit, offset = _parse_limit_offset()
    if errors:
        return validation_error(errors)

    query = Skip.query.filter_by(user_id=user_id).order_by(Skip.id.asc())
    if limit is not None:
        total = query.count()
        query = query.limit(limit).offset(offset)
    else:
        total = None

    items = [serialize_skip(s) for s in query.all()]
    if total is None:
        total = len(items)
    return api_list(items, total=total, limit=limit, offset=offset)


@api.route("/skips", methods=["POST"])
@api_login_required(require_bearer=True)
def api_create_skip():
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    body = request.get_json(silent=True) or {}
    transaction_index = body.get("transaction_index")
    schedule_id = body.get("schedule_id")
    if transaction_index is None and schedule_id is None:
        return validation_error(
            {"transaction_index": "transaction_index or schedule_id is required"}
        )

    _balance, _balance_amount, trans, _run, _run_scenario = _project_data(user_id)

    if schedule_id is not None:
        schedule = Schedule.query.filter_by(user_id=user_id, id=schedule_id).first()
        if not schedule:
            return not_found("Schedule not found")
        # Project this schedule in isolation so a matching hold (same name/type/amount)
        # or other user data can't be selected as the skip target.
        schedule_trans, _run, _run_scenario = update_cash(
            0.0, [schedule], [], [], [], commit=False
        )
        if schedule_trans.empty:
            return validation_error(
                {"schedule_id": "No upcoming transaction found for this schedule"}
            )
        tx = schedule_trans.iloc[0]
    else:
        try:
            tx = trans.loc[int(transaction_index)]
        except Exception:
            return validation_error({"transaction_index": "transaction index not found"})

    trans_type = "Income" if tx["type"] == "Expense" else "Expense"
    skip = Skip(
        name=f"{tx['name']} (SKIP)",
        type=trans_type,
        amount=tx["amount"],
        date=tx["date"],
        user_id=user_id,
    )
    db.session.add(skip)
    db.session.commit()
    return api_created(serialize_skip(skip))


@api.route("/skips/<int:skip_id>", methods=["DELETE"])
@api_login_required(require_bearer=True)
def api_delete_skip(skip_id: int):
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    skip = Skip.query.filter_by(user_id=user_id, id=skip_id).first()
    if not skip:
        return not_found("Skip not found")
    db.session.delete(skip)
    db.session.commit()
    return api_no_content()


@api.route("/skips", methods=["DELETE"])
@api_login_required(require_bearer=True)
def api_clear_skips():
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    Skip.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return api_no_content()


@api.route("/transactions", methods=["GET"])
@api_login_required
def api_transactions():
    user_id = _effective_user_id()
    _balance, _balance_amount, trans, _run, _run_scenario = _project_data(user_id)
    errors, limit, offset = _parse_limit_offset()
    if errors:
        return validation_error(errors)

    items = []
    if not trans.empty:
        for row in trans.itertuples(index=False):
            items.append({"name": row.name, "type": row.type, "amount": _amount(row.amount), "date": _date(row.date)})

    total = len(items)
    if limit is not None:
        items = items[offset:offset + limit]

    return api_list(items, total=total, limit=limit, offset=offset)


@api.route("/risk-score", methods=["GET"])
@api_login_required
def api_risk_score():
    user_id = _effective_user_id()
    _balance, balance_amount, _trans, run, _run_scenario = _project_data(user_id)
    raw = calculate_cash_risk_score(balance_amount, run)

    return api_ok({
        "score": raw["score"],
        "status": raw["status"],
        "color": raw["color"],
        "runway_days": raw["runway_days"],
        "lowest_balance": _amount(raw["lowest_balance"]),
        "days_to_lowest": raw["days_to_lowest"],
        "avg_daily_expense": _amount(raw["avg_daily_expense"]),
        "days_below_threshold": raw["days_below_threshold"],
        "pct_below_threshold": raw["pct_below_threshold"],
        "recovery_days": raw["recovery_days"],
        "near_term_buffer": _amount(raw["near_term_buffer"]),
    })


@api.route("/balance", methods=["GET"])
@api_login_required
def api_balance():
    user_id = _effective_user_id()
    balance = _latest_balance(user_id)

    if balance:
        return api_ok(serialize_balance(balance))

    todaydate = datetime.today().date()
    return api_ok({"id": None, "amount": _amount(0), "date": _date(todaydate)})


@api.route("/balance", methods=["POST"])
@api_login_required(require_bearer=True)
def api_set_balance():
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    body = request.get_json(silent=True) or {}
    errors = _validate_balance_payload(body)
    if errors:
        return validation_error(errors)

    balance_date = datetime.strptime(body.get("date") or datetime.today().date().isoformat(), "%Y-%m-%d").date()
    owner = _balance_owner_user()
    existing = (
        Balance.query.filter_by(user_id=user_id, date=balance_date)
        .order_by(desc(Balance.id))
        .first()
    )
    if existing is not None:
        existing.amount = body["amount"]
        record_manual_balance_entry(owner)
        db.session.commit()
        return api_ok(serialize_balance(existing))
    balance = Balance(user_id=user_id, amount=body["amount"], date=balance_date)
    db.session.add(balance)
    record_manual_balance_entry(owner)
    try:
        db.session.commit()
    except IntegrityError:
        # A concurrent request inserted a row for the same (user_id, date)
        # between our SELECT and INSERT. Roll back, refetch, and update.
        db.session.rollback()
        existing = Balance.query.filter_by(user_id=user_id, date=balance_date).first()
        if existing is None:
            raise
        existing.amount = body["amount"]
        record_manual_balance_entry(owner)
        db.session.commit()
        return api_ok(serialize_balance(existing))
    return api_created(serialize_balance(balance))


@api.route("/balance/history", methods=["GET"])
@api_login_required
def api_balance_history():
    user_id = _effective_user_id()
    errors, limit, offset = _parse_limit_offset()
    if errors:
        return validation_error(errors)

    query = Balance.query.filter_by(user_id=user_id).order_by(desc(Balance.date), desc(Balance.id))
    if limit is not None:
        total = query.count()
        query = query.limit(limit).offset(offset)
    else:
        total = None

    items = [serialize_balance(b) for b in query.all()]
    if total is None:
        total = len(items)
    return api_list(items, total=total, limit=limit, offset=offset)


@api.route("/settings", methods=["GET"])
@api_login_required
def api_settings():
    user = get_api_user()
    user_id = _effective_user_id()

    about = version()
    try:
        parts = about.split("::")
        app_version = parts[0].split(":", 1)[1].strip()
        py_version = parts[1].split(":", 1)[1].strip()
    except (IndexError, ValueError):
        app_version = about.strip()
        py_version = ""

    ai_config = AISettings.query.filter_by(user_id=user_id).first()
    provider = select_provider(ai_config)
    provider_kind = provider["kind"] if provider else None
    return api_ok({
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "is_admin": bool(user.admin),
            "is_global_admin": bool(user.is_global_admin),
            "is_guest": user.account_owner_id is not None,
        },
        "app": {
            "version": app_version,
            "python_version": py_version,
        },
        "ai": {
            "configured": provider is not None,
            "provider": provider_kind,
            "model": ai_config.model_version if ai_config else None,
            "last_updated": _datetime(ai_config.last_updated) if ai_config else None,
        },
    })


@api.route("/insights", methods=["GET"])
@api_login_required
def api_insights():
    user_id = _effective_user_id()
    ai_config = AISettings.query.filter_by(user_id=user_id).first()
    provider = select_provider(ai_config)

    insights = None
    if ai_config and ai_config.last_insights:
        try:
            insights = json.loads(ai_config.last_insights)
        except (json.JSONDecodeError, ValueError):
            insights = None

    return api_ok({
        "configured": provider is not None,
        "insights": insights,
        "last_updated": _datetime(ai_config.last_updated) if ai_config else None,
        "model": ai_config.model_version if ai_config else None,
    })


@api.route("/insights/refresh", methods=["POST"])
@api_login_required(require_bearer=True)
def api_insights_refresh():
    if (resp := _forbid_guest_writes()) is not None:
        return resp

    user_id = _effective_user_id()
    ai_config = AISettings.query.filter_by(user_id=user_id).first()
    provider = select_provider(ai_config)
    if not provider:
        return validation_error({"api_key": "No OpenAI API key configured"})

    last_updated = ai_config.last_updated if ai_config else None
    cached_insights = ai_config.last_insights if ai_config else None
    if not is_refresh_due(last_updated):
        try:
            parsed = json.loads(cached_insights) if cached_insights else None
        except (json.JSONDecodeError, ValueError, TypeError):
            parsed = None
        return api_ok({
            "configured": provider is not None,
            "insights": parsed,
            "last_updated": _datetime(ai_config.last_updated) if ai_config else None,
            "model": ai_config.model_version if ai_config else None,
        })

    balance_record = _latest_balance(user_id)
    current_balance = float(balance_record.amount) if balance_record else 0.0

    schedules = Schedule.query.filter_by(user_id=user_id).all()
    holds = Hold.query.filter_by(user_id=user_id).all()
    skips = Skip.query.filter_by(user_id=user_id).all()

    try:
        insights_json = fetch_insights_for_provider(provider, current_balance, schedules, holds, skips)
        insights_json, parsed = normalize_and_validate_insights_json(insights_json)
    except AIProviderError as e:
        return validation_error({"insights": e.user_message}, message="AI insights generation failed")
    except AIInsightsFormatError as e:
        return validation_error({"insights": e.user_message}, message="AI insights generation failed")
    except Exception:
        return validation_error({"insights": "Unable to generate AI insights"}, message="AI insights generation failed")

    if ai_config is None:
        ai_config = AISettings(user_id=user_id)
        db.session.add(ai_config)
    ai_config.last_insights = insights_json
    ai_config.last_updated = datetime.now(timezone.utc)
    db.session.commit()

    return api_ok({
        "configured": provider is not None,
        "insights": parsed,
        "last_updated": _datetime(ai_config.last_updated),
        "model": ai_config.model_version,
    })
