from flask import (
    request, redirect, url_for, send_from_directory, flash, send_file, Response, session, current_app
)
from flask_login import login_required, current_user, logout_user
from flask import Blueprint, render_template
from .models import (
    Schedule, Scenario, Balance, User, Settings, TextSettings, Email, Hold, Skip,
    GlobalEmailSettings, AISettings, PasskeyCredential, UserToken, PasswordSetupToken,
    Subscription, PlaidConnection,
)
from app import db, limiter
from datetime import datetime, timezone
import os
import secrets
import json
import logging
from urllib.parse import urlparse
from sqlalchemy import desc, extract, asc
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from .cashflow import update_cash, plot_cash, calculate_cash_risk_score
from .auth import admin_required, global_admin_required, account_owner_required
from .files import export, upload, version
from .getemail import send_account_activation_notification
from .getemail import send_password_setup_email
from .crypto_utils import encrypt_password, decrypt_password
from .ai_insights import (
    AIProviderError,
    fetch_insights,
    fetch_insights_for_provider,
    is_refresh_due,
    AIInsightsFormatError,
    normalize_and_validate_insights_json,
    select_provider,
    validate_model,
)
from .password_setup import create_password_setup_link
from .plaid_service import (
    safe_update_plaid_balance_for_user,
    realtime_update_plaid_balance_for_user,
    remove_plaid_connections_for_user_ids,
    record_manual_balance_entry,
)
from .totp_utils import (
    generate_totp_secret, encrypt_totp_secret, decrypt_totp_secret,
    generate_qr_code_b64, verify_totp,
    generate_backup_codes, hash_backup_codes,
    verify_and_consume_backup_code,
)


main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

# Input validation constants
_VALID_TYPES = {'Income', 'Expense'}
_VALID_FREQUENCIES = {'Monthly', 'Quarterly', 'Yearly', 'Weekly', 'BiWeekly', 'Onetime'}
_MAX_NAME_LEN = 100
_MAX_EMAIL_LEN = 254


def get_effective_user_id():
    """
    Get the effective user ID for data filtering.
    For guest users, returns their account owner's ID.
    For account owners, returns their own ID.
    """
    owner_id = current_user.owner_user_id or current_user.account_owner_id
    if owner_id:
        # Guest user - return account owner's ID
        return owner_id
    else:
        # Account owner or standalone user - return their own ID
        return current_user.id


def _get_balance_owner_user():
    """Return the User whose balance is the source of truth for the request."""
    effective_id = get_effective_user_id()
    if effective_id == current_user.id:
        return current_user._get_current_object()
    return User.query.get(effective_id)


@main.route('/', methods=('GET', 'POST'))
@login_required
def index():
    # Get effective user ID (account owner for guests, self for owners)
    user_id = get_effective_user_id()

    # Refresh today's balance from Plaid (no-op if not configured/connected).
    safe_update_plaid_balance_for_user(_get_balance_owner_user())

    # get today's date
    todaydate = datetime.today().strftime('%A, %B %d, %Y')

    # query the latest balance information for this user
    balance = Balance.query.filter_by(user_id=user_id).order_by(desc(Balance.date), desc(Balance.id)).first()

    if balance is None:
        balance = Balance(amount='0', date=datetime.today(), user_id=user_id)
        db.session.add(balance)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            balance = Balance.query.filter_by(user_id=user_id).order_by(
                desc(Balance.date), desc(Balance.id)
            ).first()
    else:
        try:
            float(balance.amount)
        except (ValueError, TypeError, AttributeError) as exc:
            logger.warning("Invalid balance for user %s (%s), resetting to 0: %s", user_id, type(exc).__name__, exc)
            balance.amount = '0'
            balance.date = datetime.today()
            db.session.commit()

    # Pre-filter data by user before passing to cashflow
    schedules = Schedule.query.filter_by(user_id=user_id).all()
    holds = Hold.query.filter_by(user_id=user_id).all()
    skips = Skip.query.filter_by(user_id=user_id).all()
    scenarios = Scenario.query.filter_by(user_id=user_id).all()

    trans, run, run_scenario = update_cash(float(balance.amount), schedules, holds, skips, scenarios)

    # plot cash flow results
    minbalance, min_scenario, graphJSON = plot_cash(run, run_scenario)

    # calculate cash risk score
    cash_risk = calculate_cash_risk_score(float(balance.amount), run)

    # Load AI insights for dashboard card (uses effective user_id so guests see owner's insights)
    ai_config = AISettings.query.filter_by(user_id=user_id).first()
    ai_insights_data = None
    ai_last_updated = None
    ai_provider_configured = False
    if ai_config:
        ai_last_updated = ai_config.last_updated
        if ai_config.last_insights:
            try:
                ai_insights_data = json.loads(ai_config.last_insights)
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning("Could not parse cached AI insights for user %s: %s", user_id, exc)
    ai_provider_configured = select_provider(ai_config) is not None

    if current_user.admin:
        return render_template('index.html', title='Index', todaydate=todaydate, balance=balance.amount,
                           minbalance=minbalance, min_scenario=min_scenario, graphJSON=graphJSON,
                           ai_insights_data=ai_insights_data, ai_last_updated=ai_last_updated,
                           ai_provider_configured=ai_provider_configured, cash_risk=cash_risk)
    else:
        return render_template('index_guest.html', title='Index', todaydate=todaydate, balance=balance.amount,
                           minbalance=minbalance, min_scenario=min_scenario, graphJSON=graphJSON,
                           ai_insights_data=ai_insights_data, ai_last_updated=ai_last_updated,
                           cash_risk=cash_risk)


@main.route('/refresh')
@login_required
def refresh():

    return redirect(url_for('main.index'))


@main.route('/settings')
@login_required
def settings():
    # get about info - available to all users
    about = version()
    try:
        _parts = about.split('::')
        app_version = _parts[0].split(':', 1)[1].strip()
        py_version = _parts[1].split(':', 1)[1].strip()
    except (IndexError, ValueError):
        app_version = about.strip()
        py_version = ''
    user_id = get_effective_user_id()

    if current_user.admin:
        ai_config = AISettings.query.filter_by(user_id=current_user.id).first()
        ai_configured = ai_config is not None and bool(ai_config.api_key)
        ai_model = ai_config.model_version if ai_config else ''
        email_config = Email.query.filter_by(user_id=user_id).first()
        global_email_config = GlobalEmailSettings.query.first()
        signup_setting = Settings.query.filter_by(name='signup').first()
        signup_link_setting = TextSettings.query.filter_by(name='external_signup_url').first()
        return render_template('settings.html', about=about, app_version=app_version, py_version=py_version,
                             ai_configured=ai_configured, ai_model=ai_model,
                             email_config=email_config, global_email_config=global_email_config,
                             signup_setting=signup_setting, signup_link_setting=signup_link_setting)
    else:
        email_config = Email.query.filter_by(user_id=user_id).first()
        signup_setting = Settings.query.filter_by(name='signup').first()
        signup_link_setting = TextSettings.query.filter_by(name='external_signup_url').first()
        return render_template('settings_guest.html', about=about, app_version=app_version, py_version=py_version,
                             email_config=email_config, signup_setting=signup_setting,
                             signup_link_setting=signup_link_setting)


@main.route('/schedule')
@login_required
@admin_required
def schedule():
    user_id = get_effective_user_id()
    schedule = Schedule.query.filter_by(user_id=user_id).order_by(asc(extract('day', Schedule.startdate)))

    return render_template('schedule_table.html', title='Schedule Table', schedule=schedule)


@main.route('/holds')
@login_required
@admin_required
def holds():
    user_id = get_effective_user_id()
    hold = Hold.query.filter_by(user_id=user_id)
    skip = Skip.query.filter_by(user_id=user_id)

    return render_template('holds_table.html', title='Holds Table', hold=hold, skip=skip)


@main.route('/create', methods=('GET', 'POST'))
@login_required
@admin_required
def create():
    # create a new schedule item
    user_id = get_effective_user_id()
    format = '%Y-%m-%d'
    if request.method == 'POST':
        name = request.form['name'].strip()
        amount = request.form['amount']
        frequency = request.form['frequency']
        startdate = request.form['startdate']
        type = request.form['type']

        if not name or len(name) > _MAX_NAME_LEN:
            flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
            return redirect(url_for('main.schedule'))
        try:
            float(amount)
        except (ValueError, TypeError):
            flash("Amount must be a number")
            return redirect(url_for('main.schedule'))
        if type not in _VALID_TYPES:
            flash("Invalid type")
            return redirect(url_for('main.schedule'))
        if frequency not in _VALID_FREQUENCIES:
            flash("Invalid frequency")
            return redirect(url_for('main.schedule'))

        schedule = Schedule(name=name,
                            type=type,
                            amount=amount,
                            frequency=frequency,
                            startdate=datetime.strptime(startdate, format).date(),
                            firstdate=datetime.strptime(startdate, format).date(),
                            user_id=user_id)
        existing = Schedule.query.filter_by(name=name, user_id=user_id).first()
        if existing:
            flash("Schedule already exists")
            return redirect(url_for('main.schedule'))
        db.session.add(schedule)
        db.session.commit()
        flash("Added Successfully")

        return redirect(url_for('main.schedule'))

    return redirect(url_for('main.schedule'))


@main.route('/update', methods=['GET', 'POST'])
@login_required
@admin_required
def update():
    # update an existing schedule item
    user_id = get_effective_user_id()
    format = '%Y-%m-%d'

    if request.method == 'POST':
        new_name = request.form['name'].strip()
        new_amount = request.form['amount']
        new_type = request.form['type']
        new_frequency = request.form['frequency']

        if not new_name or len(new_name) > _MAX_NAME_LEN:
            flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
            return redirect(url_for('main.schedule'))
        try:
            float(new_amount)
        except (ValueError, TypeError):
            flash("Amount must be a number")
            return redirect(url_for('main.schedule'))
        if new_type not in _VALID_TYPES:
            flash("Invalid type")
            return redirect(url_for('main.schedule'))
        if new_frequency not in _VALID_FREQUENCIES:
            flash("Invalid frequency")
            return redirect(url_for('main.schedule'))

        current = Schedule.query.filter_by(id=int(request.form['id']), user_id=user_id).first()
        if not current:
            flash("Schedule not found")
            return redirect(url_for('main.schedule'))
        existing = Schedule.query.filter_by(name=new_name, user_id=user_id).first()
        if existing:
            if current.name != new_name:
                flash("Schedule name already exists")
                return redirect(url_for('main.schedule'))
        my_data = current
        my_data.name = new_name
        my_data.amount = new_amount
        my_data.type = new_type
        my_data.frequency = new_frequency
        startdate = request.form['startdate']
        if (datetime.strptime(startdate, format).date() != my_data.startdate and my_data.startdate.day !=
                datetime.strptime(startdate, format).day):
            my_data.firstdate = datetime.strptime(startdate, format).date()
        my_data.startdate = datetime.strptime(startdate, format).date()
        db.session.commit()
        flash("Updated Successfully")

        return redirect(url_for('main.schedule'))

    return redirect(url_for('main.schedule'))


@main.route('/addhold/<id>', methods=['POST'])
@login_required
@admin_required
def addhold(id):
    # add a hold item from the schedule
    user_id = get_effective_user_id()
    schedule = Schedule.query.filter_by(id=int(id), user_id=user_id).first()
    if not schedule:
        flash("Schedule not found")
        return redirect(url_for('main.schedule'))
    hold = Hold(name=schedule.name, type=schedule.type, amount=schedule.amount, user_id=user_id)
    db.session.add(hold)
    db.session.commit()
    flash("Added Hold")

    return redirect(url_for('main.schedule'))


@main.route('/addskip/<id>', methods=['POST'])
@login_required
@admin_required
def addskip(id):
    # add a skip item from the schedule
    user_id = get_effective_user_id()
    balance = Balance.query.filter_by(user_id=user_id).order_by(desc(Balance.date), desc(Balance.id)).first()

    # Pre-filter data by user
    schedules = Schedule.query.filter_by(user_id=user_id).all()
    holds = Hold.query.filter_by(user_id=user_id).all()
    skips = Skip.query.filter_by(user_id=user_id).all()

    trans, run, _ = update_cash(float(balance.amount) if balance else 0.0, schedules, holds, skips)
    if int(id) not in trans.index:
        flash("Transaction not found")
        return redirect(url_for('main.transactions'))
    transaction = trans.loc[int(id)]
    trans_type = ""
    if transaction['type'] == "Expense":
        trans_type = "Income"
    elif transaction['type'] == "Income":
        trans_type = "Expense"
    skip = Skip(name=transaction['name'] + " (SKIP)", type=trans_type, amount=transaction['amount'], date=transaction['date'], user_id=user_id)
    db.session.add(skip)
    db.session.commit()
    flash("Added Skip")

    return redirect(url_for('main.transactions'))


@main.route('/deletehold/<id>', methods=['POST'])
@login_required
@admin_required
def holds_delete(id):
    # delete a hold item
    user_id = get_effective_user_id()
    hold = Hold.query.filter_by(id=int(id), user_id=user_id).first()

    if hold:
        db.session.delete(hold)
        db.session.commit()
        flash("Deleted Successfully")

    return redirect(url_for('main.holds'))


@main.route('/deleteskip/<id>', methods=['POST'])
@login_required
@admin_required
def skips_delete(id):
    # delete a skip item
    user_id = get_effective_user_id()
    skip = Skip.query.filter_by(id=int(id), user_id=user_id).first()

    if skip:
        db.session.delete(skip)
        db.session.commit()
        flash("Deleted Successfully")

    return redirect(url_for('main.holds'))


@main.route('/clearholds', methods=['POST'])
@login_required
@admin_required
def clear_holds():
    # clear holds
    user_id = get_effective_user_id()
    db.session.query(Hold).filter_by(user_id=user_id).delete()
    db.session.commit()

    return redirect(url_for('main.holds'))


@main.route('/clearskips', methods=['POST'])
@login_required
@admin_required
def clear_skips():
    # clear skips
    user_id = get_effective_user_id()
    db.session.query(Skip).filter_by(user_id=user_id).delete()
    db.session.commit()

    return redirect(url_for('main.holds'))


@main.route('/delete/<id>', methods=['POST'])
@login_required
@admin_required
def schedule_delete(id):
    # delete a schedule item
    user_id = get_effective_user_id()
    schedule = Schedule.query.filter_by(id=int(id), user_id=user_id).first()

    if schedule:
        db.session.delete(schedule)
        db.session.commit()
        flash("Deleted Successfully")

    return redirect(url_for('main.schedule'))


@main.route('/scenarios')
@login_required
@admin_required
def scenarios():
    user_id = get_effective_user_id()
    scenario = Scenario.query.filter_by(user_id=user_id).order_by(asc(extract('day', Scenario.startdate)))

    return render_template('scenario_table.html', title='Scenario Table', scenario=scenario)


@main.route('/create_scenario', methods=('GET', 'POST'))
@login_required
@admin_required
def create_scenario():
    user_id = get_effective_user_id()
    format = '%Y-%m-%d'
    if request.method == 'POST':
        name = request.form['name'].strip()
        amount = request.form['amount']
        frequency = request.form['frequency']
        startdate = request.form['startdate']
        type = request.form['type']

        if not name or len(name) > _MAX_NAME_LEN:
            flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
            return redirect(url_for('main.scenarios'))
        try:
            float(amount)
        except (ValueError, TypeError):
            flash("Amount must be a number")
            return redirect(url_for('main.scenarios'))
        if type not in _VALID_TYPES:
            flash("Invalid type")
            return redirect(url_for('main.scenarios'))
        if frequency not in _VALID_FREQUENCIES:
            flash("Invalid frequency")
            return redirect(url_for('main.scenarios'))

        scenario = Scenario(name=name,
                            type=type,
                            amount=amount,
                            frequency=frequency,
                            startdate=datetime.strptime(startdate, format).date(),
                            firstdate=datetime.strptime(startdate, format).date(),
                            user_id=user_id)
        existing = Scenario.query.filter_by(name=name, user_id=user_id).first()
        if existing:
            flash("Scenario already exists")
            return redirect(url_for('main.scenarios'))
        db.session.add(scenario)
        db.session.commit()
        flash("Added Successfully")

        return redirect(url_for('main.scenarios'))

    return redirect(url_for('main.scenarios'))


@main.route('/update_scenario', methods=['GET', 'POST'])
@login_required
@admin_required
def update_scenario():
    user_id = get_effective_user_id()
    format = '%Y-%m-%d'

    if request.method == 'POST':
        new_name = request.form['name'].strip()
        new_amount = request.form['amount']
        new_type = request.form['type']
        new_frequency = request.form['frequency']

        if not new_name or len(new_name) > _MAX_NAME_LEN:
            flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
            return redirect(url_for('main.scenarios'))
        try:
            float(new_amount)
        except (ValueError, TypeError):
            flash("Amount must be a number")
            return redirect(url_for('main.scenarios'))
        if new_type not in _VALID_TYPES:
            flash("Invalid type")
            return redirect(url_for('main.scenarios'))
        if new_frequency not in _VALID_FREQUENCIES:
            flash("Invalid frequency")
            return redirect(url_for('main.scenarios'))

        current = Scenario.query.filter_by(id=int(request.form['id']), user_id=user_id).first()
        if not current:
            flash("Scenario not found")
            return redirect(url_for('main.scenarios'))
        existing = Scenario.query.filter_by(name=new_name, user_id=user_id).first()
        if existing and current.name != new_name:
            flash("Scenario name already exists")
            return redirect(url_for('main.scenarios'))
        current.name = new_name
        current.amount = new_amount
        current.type = new_type
        current.frequency = new_frequency
        startdate = request.form['startdate']
        if (datetime.strptime(startdate, format).date() != current.startdate and current.startdate.day !=
                datetime.strptime(startdate, format).day):
            current.firstdate = datetime.strptime(startdate, format).date()
        current.startdate = datetime.strptime(startdate, format).date()
        db.session.commit()
        flash("Updated Successfully")

        return redirect(url_for('main.scenarios'))

    return redirect(url_for('main.scenarios'))


@main.route('/delete_scenario/<id>', methods=['POST'])
@login_required
@admin_required
def scenario_delete(id):
    user_id = get_effective_user_id()
    scenario = Scenario.query.filter_by(id=int(id), user_id=user_id).first()

    if scenario:
        db.session.delete(scenario)
        db.session.commit()
        flash("Deleted Successfully")

    return redirect(url_for('main.scenarios'))


@main.route('/favicon')
def favicon():
    return send_from_directory(os.path.join(main.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@main.route('/appleicon')
def appleicon():
    return send_from_directory(os.path.join(main.root_path, 'static'),
                               'apple-touch-icon.png', mimetype='image/png')


@main.route('/.well-known/apple-app-site-association', methods=['GET'])
def apple_app_site_association():
    return send_from_directory(
        os.path.join(main.root_path, '.well-known'),
        'apple-app-site-association',
        mimetype='application/json',
    )


@main.route('/healthz', methods=['GET'])
@limiter.exempt
def healthz():
    # Liveness probe for the Docker HEALTHCHECK. Must stay auth-free,
    # redirect-free, and side-effect-free so it doesn't pollute access logs
    # or trigger the dashboard Plaid balance refresh.
    return Response('ok', status=200, mimetype='text/plain')


@main.route('/refresh_realtime_balance', methods=['POST'])
@login_required
@admin_required
@limiter.limit("60 per hour")
def refresh_realtime_balance():
    """Trigger a paid Plaid /accounts/balance/get refresh from the dashboard.

    Rate-limited server-side to once every 24 hours per connection. The
    dashboard route re-runs after the redirect, so any new balance is
    reflected immediately.
    """
    owner = _get_balance_owner_user()
    try:
        result = realtime_update_plaid_balance_for_user(owner)
    except Exception:
        logger.exception(
            "Real-time Plaid balance refresh failed for user %s",
            getattr(owner, "id", None),
        )
        flash(
            "Could not refresh balance from Plaid. Please try again later.",
            "error",
        )
        return redirect(url_for('main.index'))

    status = result.get("status")
    reason = result.get("reason")
    if status == "ok":
        flash("Live balance refreshed.")
    elif status == "rate_limited":
        retry_after = int(result.get("retry_after_seconds") or 0)
        hours = max(1, (retry_after + 1800) // 3600)
        flash(
            "Live refresh is available once every 24 hours. "
            f"Try again in about {hours} hour(s).",
            "error",
        )
    elif status == "skipped" and reason == "no_connection":
        flash(
            "Connect a Plaid account in Settings > More Settings.",
            "error",
        )
    elif status == "skipped" and reason == "not_configured":
        flash(
            "Live refresh is unavailable right now. Your cached Plaid balance "
            "will still update automatically.",
            "error",
        )
    elif status == "skipped" and reason == "no_balance_value":
        flash("Plaid did not return a balance for this account.", "error")
    else:
        flash(
            "Live refresh is unavailable right now. Your cached Plaid balance "
            "will still update automatically.",
            "error",
        )

    # The dashboard route re-runs after this redirect, so any new balance row
    # is picked up immediately via the existing dashboard calculation helper.
    return redirect(url_for('main.index'))


@main.route('/balance', methods=('GET', 'POST'))
@login_required
@admin_required
def balance():
    # manually update the balance from the balance button
    user_id = get_effective_user_id()
    format = '%Y-%m-%d'
    if request.method == 'POST':
        amount = request.form['amount']
        dateentry = request.form['date']
        balance_date = datetime.strptime(dateentry, format).date()
        owner = _get_balance_owner_user()
        existing = (
            Balance.query.filter_by(user_id=user_id, date=balance_date)
            .order_by(desc(Balance.id))
            .first()
        )
        if existing is not None:
            existing.amount = amount
            record_manual_balance_entry(owner)
            db.session.commit()
        else:
            db.session.add(Balance(amount=amount, date=balance_date, user_id=user_id))
            record_manual_balance_entry(owner)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                existing = Balance.query.filter_by(user_id=user_id, date=balance_date).first()
                if existing is None:
                    raise
                existing.amount = amount
                record_manual_balance_entry(owner)
                db.session.commit()

    return redirect(url_for('main.index'))


@main.route('/changepw', methods=('GET', 'POST'))
@login_required
@limiter.limit("5 per minute")
def changepw():
    # update account profile (name, email) and optionally change password
    if request.method == 'POST':
        my_user = User.query.filter_by(id=current_user.id).first()
        current = request.form['current']
        new_name = request.form.get('name', '').strip()
        new_email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password2', '').strip()

        if not check_password_hash(my_user.password, current):
            flash('Incorrect current password')
            return redirect(url_for('main.settings'))

        # Validate new email if it changed
        if new_email and new_email != my_user.email.lower():
            existing = User.query.filter(
                db.func.lower(User.email) == new_email,
                User.id != my_user.id
            ).first()
            if existing:
                flash('That email address is already in use')
                return redirect(url_for('main.settings'))
            my_user.email = new_email

        if new_name:
            my_user.name = new_name

        # Only update password if the user filled in the new password fields
        if password or password2:
            if not password or not password2:
                flash('Please fill in both new password fields')
                return redirect(url_for('main.settings'))
            if password != password2:
                flash('New passwords do not match')
                return redirect(url_for('main.settings'))
            if len(password) < 8:
                flash('New password must be at least 8 characters')
                return redirect(url_for('main.settings'))
            my_user.password = generate_password_hash(password, method='scrypt')

        db.session.commit()
        flash('Account settings updated successfully')
        return redirect(url_for('main.settings'))

    return redirect(url_for('main.settings'))


@main.route('/signups', methods=('GET', 'POST'))
@login_required
@global_admin_required
def signups():
    # set the settings options, in this case disable signups, from the profile page
    if request.method == 'POST':
        external_signup_url = (request.form.get('external_signup_url') or '').strip()
        if external_signup_url:
            parsed_url = urlparse(external_signup_url)
            if parsed_url.scheme not in ('http', 'https') or not parsed_url.netloc:
                flash('External sign-up URL must be a valid http(s) URL')
                return redirect(url_for('main.settings'))

        signupsettingname = Settings.query.filter_by(name='signup').first()
        signup_link_setting = TextSettings.query.filter_by(name='external_signup_url').first()

        if signupsettingname:
            if request.form['signupvalue'] == "True":
                signupvalue = True
            else:
                signupvalue = False
            signupsettingname.value = signupvalue
            if signup_link_setting:
                signup_link_setting.value = external_signup_url or None
            else:
                db.session.add(
                    TextSettings(name='external_signup_url', value=external_signup_url or None)
                )
            db.session.commit()

            return redirect(url_for('main.settings'))

        # store the signup option value in the database to check when the user clicks signup
        if request.form['signupvalue'] == "True":
            signupvalue = True
        else:
            signupvalue = False
        settings = Settings(name="signup", value=signupvalue)
        db.session.add(settings)
        if signup_link_setting:
            signup_link_setting.value = external_signup_url or None
        else:
            db.session.add(
                TextSettings(name='external_signup_url', value=external_signup_url or None)
            )
        db.session.commit()

        return redirect(url_for('main.settings'))

    return redirect(url_for('main.settings'))


@main.route('/transactions')
@login_required
@admin_required
def transactions():
    user_id = get_effective_user_id()
    balance = Balance.query.filter_by(user_id=user_id).order_by(desc(Balance.date), desc(Balance.id)).first()

    # Pre-filter data by user
    schedules = Schedule.query.filter_by(user_id=user_id).all()
    holds = Hold.query.filter_by(user_id=user_id).all()
    skips = Skip.query.filter_by(user_id=user_id).all()

    trans, run, _ = update_cash(float(balance.amount) if balance else 0.0, schedules, holds, skips)

    return render_template('transactions_table.html', total=trans.to_dict(orient='records'))


@main.route('/email', methods=('GET', 'POST'))
@login_required
@admin_required
def email():
    # set the users email address, password, and server for the auto email balance update
    user_id = get_effective_user_id()

    if request.method == 'POST':
        emailsettings = Email.query.filter_by(user_id=user_id).first()

        if emailsettings:
            email = request.form['email']
            password_input = request.form.get('password', '').strip()
            server = request.form['server']
            subjectstr = request.form['subject_str']
            startstr = request.form['start_str']
            endstr = request.form['end_str']
            allowed_sender = request.form.get('allowed_sender', '').strip().lower() or None
            emailsettings.email = email
            if password_input:
                emailsettings.password = encrypt_password(password_input)
            emailsettings.server = server
            emailsettings.subjectstr = subjectstr
            emailsettings.startstr = startstr
            emailsettings.endstr = endstr
            emailsettings.allowed_sender = allowed_sender
            db.session.commit()

            return redirect(url_for('main.settings'))

        email = request.form['email']
        password = encrypt_password(request.form['password'])
        server = request.form['server']
        subjectstr = request.form['subject_str']
        startstr = request.form['start_str']
        endstr = request.form['end_str']
        allowed_sender = request.form.get('allowed_sender', '').strip().lower() or None
        emailentry = Email(email=email, password=password, server=server, subjectstr=subjectstr, startstr=startstr,
                           endstr=endstr, allowed_sender=allowed_sender, user_id=user_id)
        db.session.add(emailentry)
        db.session.commit()

        return redirect(url_for('main.settings'))

    return redirect(url_for('main.settings'))


@main.route('/email/delete', methods=['POST'])
@login_required
@admin_required
def email_delete():
    # remove the user's email balance update settings
    user_id = get_effective_user_id()
    deleted = Email.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    if deleted:
        flash('Email balance update settings removed')
    else:
        flash('No email balance update settings to remove')

    return redirect(url_for('main.settings'))


@main.route('/update_user', methods=['GET', 'POST'])
@login_required
@admin_required
def update_user():
    # update an existing user
    if request.method == 'POST':
        current = User.query.filter_by(id=int(request.form['id'])).first()

        if not current:
            flash("User not found")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            else:
                return redirect(url_for('main.manage_guests'))

        # Check if the current user has permission to update this user
        if not current_user.is_global_admin and current.account_owner_id != current_user.id:
            flash("You don't have permission to update this user")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            else:
                return redirect(url_for('main.manage_guests'))

        new_name = request.form['name'].strip()
        new_email = request.form['email'].strip().lower()

        if not new_name or len(new_name) > _MAX_NAME_LEN:
            flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            return redirect(url_for('main.manage_guests'))
        if not new_email or len(new_email) > _MAX_EMAIL_LEN:
            flash(f"Email must be between 1 and {_MAX_EMAIL_LEN} characters")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            return redirect(url_for('main.manage_guests'))

        # Use a single query that excludes the current user to avoid TOCTOU;
        # the unique constraint on email also protects against concurrent races.
        existing = User.query.filter(
            db.func.lower(User.email) == new_email,
            User.id != current.id
        ).first()
        if existing:
            flash("Email already exists")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            else:
                return redirect(url_for('main.manage_guests'))
        # Reuse the already-fetched 'current' object instead of issuing a second query
        current.name = new_name
        current.email = new_email

        # Global admins can change roles, Account Owners cannot.
        # Guest accounts are permanent: once a guest, always a guest. Any
        # posted role for a guest is ignored so a guest can never be promoted
        # (which would leave them with inconsistent ownership links).
        is_guest = current.account_owner_id is not None or current.owner_user_id is not None
        if current_user.is_global_admin and not is_guest:
            # Handle role assignment
            role = request.form.get('role')
            if role == 'global_admin':
                current.admin = True
                current.is_global_admin = True
                # IMPORTANT: Global admins must always be active
                current.is_active = True
            elif role == 'admin':
                current.admin = True
                current.is_global_admin = False
            # Any other value is ignored: non-guests cannot be demoted to
            # guests either, since real guests are created via add_guest and
            # must be linked to an account owner.

        db.session.commit()
        flash("Updated Successfully")

        # Redirect based on user role
        if current_user.is_global_admin:
            return redirect(url_for('main.global_admin_panel'))
        else:
            return redirect(url_for('main.manage_guests'))

    # Redirect based on user role
    if current_user.is_global_admin:
        return redirect(url_for('main.global_admin_panel'))
    else:
        return redirect(url_for('main.manage_guests'))


def _delete_user_owned_rows(user_ids):
    # Bulk-delete every FK-linked row owned by the given user IDs.
    # Bulk deletes bypass ORM cascades, so each table with a user_id FK
    # must be cleared explicitly to avoid integrity errors.
    if not user_ids:
        return

    for model in (
        PasswordSetupToken,
        UserToken,
        PasskeyCredential,
        AISettings,
        Subscription,
        PlaidConnection,
        Email,
        Skip,
        Hold,
        Balance,
        Scenario,
        Schedule,
    ):
        db.session.query(model).filter(
            model.user_id.in_(user_ids)
        ).delete(synchronize_session=False)


def _cascade_delete_user(user):
    # Manually delete all related data before deleting the user, then commit.
    user_id = user.id

    # Clear FK-linked rows for every guest before bulk-deleting guest User rows.
    guest_ids = [
        guest_id for (guest_id,) in db.session.query(User.id).filter_by(account_owner_id=user_id).all()
    ]

    # Best-effort: tell Plaid the Items are gone so we stop being billed for
    # the Transactions subscription. Must run before the bulk delete clears
    # PlaidConnection rows (we need the access tokens).
    remove_plaid_connections_for_user_ids([user_id] + guest_ids)

    _delete_user_owned_rows(guest_ids)
    if guest_ids:
        db.session.query(User).filter(User.id.in_(guest_ids)).delete(synchronize_session=False)

    # Clear FK-linked rows for the user themselves.
    _delete_user_owned_rows([user_id])

    # Now delete the user
    db.session.delete(user)
    db.session.commit()


@main.route('/delete_user/<id>', methods=['POST'])
@login_required
@admin_required
def delete_user(id):
    # delete a user
    user = User.query.filter_by(id=int(id)).first()

    if user:
        # Global admins can delete any user (except themselves), Account Owners can only delete their guests
        if current_user.is_global_admin or user.account_owner_id == current_user.id:
            # Prevent deleting yourself
            if user.id == current_user.id:
                flash("You cannot delete your own account")
                if current_user.is_global_admin:
                    return redirect(url_for('main.global_admin_panel'))
                else:
                    return redirect(url_for('main.manage_guests'))

            _cascade_delete_user(user)
            flash("Deleted Successfully")
        else:
            flash("You don't have permission to delete this user")

    # Redirect based on user role
    if current_user.is_global_admin:
        return redirect(url_for('main.global_admin_panel'))
    else:
        return redirect(url_for('main.manage_guests'))


@main.route('/delete_my_account', methods=['POST'])
@login_required
@account_owner_required
@limiter.limit("5 per minute")
def delete_my_account():
    # Account owners can permanently delete their own account, all guests, and all associated data.
    # Global admins are blocked from this self-service path so the platform always retains
    # at least one admin able to manage users; they must demote themselves first.
    if current_user.is_global_admin:
        flash('Global admins cannot delete their own account from this page')
        return redirect(url_for('main.settings'))

    username = (request.form.get('username') or '').strip().lower()
    password = request.form.get('password') or ''

    user = User.query.filter_by(id=current_user.id).first()

    if not user or not username or not password \
            or username != (user.email or '').lower() \
            or not check_password_hash(user.password, password):
        flash('Username or password is incorrect')
        return redirect(url_for('main.settings'))

    _cascade_delete_user(user)

    session.clear()
    logout_user()
    flash('Your account has been deleted')
    return redirect(url_for('auth.login'))


@main.route('/activate_user/<id>', methods=['POST'])
@login_required
@admin_required
def activate_user(id):
    # activate a user account
    user = User.query.filter_by(id=int(id)).first()

    if user:
        # Global admins can activate any user, Account Owners can only activate their guests
        if current_user.is_global_admin or user.account_owner_id == current_user.id:
            user.is_active = True
            db.session.commit()
            flash(f"User {user.name} has been activated successfully")

            # Send activation notification email to the user
            try:
                send_account_activation_notification(user.name, user.email)
            except Exception as exc:
                # Don't fail activation if email notification fails
                logger.warning("Failed to send activation notification to %s: %s", user.email, exc)
        else:
            flash("You don't have permission to activate this user")

    # Redirect based on user role
    if current_user.is_global_admin:
        return redirect(url_for('main.global_admin_panel'))
    else:
        return redirect(url_for('main.manage_guests'))


@main.route('/deactivate_user/<id>', methods=['POST'])
@login_required
@admin_required
def deactivate_user(id):
    # deactivate a user account
    user = User.query.filter_by(id=int(id)).first()

    if user:
        # IMPORTANT: Global admins are always active and cannot be deactivated
        if user.is_global_admin:
            flash("Cannot deactivate a global admin. Global admins must always remain active.")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            else:
                return redirect(url_for('main.manage_guests'))

        # Global admins can deactivate any user, Account Owners can only deactivate their guests
        if current_user.is_global_admin or user.account_owner_id == current_user.id:
            user.is_active = False
            db.session.commit()
            flash(f"User {user.name} has been deactivated successfully")
        else:
            flash("You don't have permission to deactivate this user")

    # Redirect based on user role
    if current_user.is_global_admin:
        return redirect(url_for('main.global_admin_panel'))
    else:
        return redirect(url_for('main.manage_guests'))


@main.route('/toggle_review_user/<id>', methods=['POST'])
@login_required
@global_admin_required
def toggle_review_user(id):
    """Mark/unmark an account owner as an Apple-review test account.

    Reviewer accounts bypass payment-subscription enforcement and remain
    active so the App Store review team can exercise the app without a
    purchased subscription.
    """
    user = User.query.filter_by(id=int(id)).first()

    if not user:
        flash("User not found")
        return redirect(url_for('main.global_admin_panel'))

    if user.account_owner_id is not None:
        flash("Reviewer flag can only be toggled on account owners")
        return redirect(url_for('main.global_admin_panel'))

    user.is_review_user = not bool(user.is_review_user)
    if user.is_review_user:
        user.is_active = True
    db.session.commit()

    if user.is_review_user:
        flash(f"User {user.name} is now a reviewer account (subscription exempt)")
    else:
        flash(f"User {user.name} is no longer a reviewer account")

    return redirect(url_for('main.global_admin_panel'))


@main.route('/create_user', methods=('GET', 'POST'))
@login_required
@admin_required
def create_user():
    # create a new user
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        raw_password = request.form['password']

        if not name or len(name) > _MAX_NAME_LEN:
            flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            return redirect(url_for('main.manage_guests'))
        if not email or len(email) > _MAX_EMAIL_LEN:
            flash(f"Email must be between 1 and {_MAX_EMAIL_LEN} characters")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            return redirect(url_for('main.manage_guests'))
        if not raw_password or len(raw_password) < 8:
            flash("Password must be at least 8 characters")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            return redirect(url_for('main.manage_guests'))

        password = generate_password_hash(raw_password, method='scrypt')

        # Handle role assignment
        role = request.form.get('role', 'guest')

        # Global admins can create any type of user
        if current_user.is_global_admin:
            if role == 'global_admin':
                admin = True
                is_global_admin = True
            elif role == 'admin':
                admin = True
                is_global_admin = False
            else:  # guest
                admin = False
                is_global_admin = False
            account_owner_id = None
            # Users created by global admin are active by default
            is_active = True
        else:
            # Account Owners can only create guest users
            admin = False
            is_global_admin = False
            account_owner_id = current_user.id
            # Guests created by Account Owners are active by default
            is_active = True

        # Check uniqueness before constructing the User object to avoid TOCTOU
        existing = User.query.filter(db.func.lower(User.email) == email).first()
        if existing:
            flash("User already exists")
            if current_user.is_global_admin:
                return redirect(url_for('main.global_admin_panel'))
            else:
                return redirect(url_for('main.manage_guests'))
        user = User(name=name, email=email, admin=admin, is_global_admin=is_global_admin,
                    is_active=is_active, password=password, account_owner_id=account_owner_id,
                    owner_user_id=account_owner_id, is_account_owner=account_owner_id is None)
        db.session.add(user)
        db.session.commit()
        flash("Added Successfully")

        # Redirect based on user role
        if current_user.is_global_admin:
            return redirect(url_for('main.global_admin_panel'))
        else:
            return redirect(url_for('main.manage_guests'))

    # Redirect based on user role
    if current_user.is_global_admin:
        return redirect(url_for('main.global_admin_panel'))
    else:
        return redirect(url_for('main.manage_guests'))


@main.route('/export', methods=('GET', 'POST'))
@login_required
@admin_required
def export_csv():
    user_id = get_effective_user_id()

    csv_data = export(user_id)

    # Create a direct download response with the CSV data and appropriate headers
    response = Response(csv_data, content_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=schedule_export.csv"

    return response


@main.route('/import', methods=['POST'])
@login_required
@admin_required
def import_csv():
    user_id = get_effective_user_id()
    csv_file = request.files.get('file')

    try:
        success_count, error_count = upload(csv_file, user_id)
        if error_count:
            flash(f"Import completed: {success_count} row(s) imported, {error_count} row(s) skipped due to validation errors.")
        else:
            flash(f"Import successful: {success_count} row(s) imported.")
    except ValueError as e:
        flash(str(e))

    return redirect(url_for('main.schedule'))


@main.route('/manage_guests')
@login_required
@account_owner_required
def manage_guests():
    """Account owners can manage their guest users"""
    guests = User.query.filter_by(account_owner_id=current_user.id).all()
    return render_template('manage_guests.html', guests=guests)


@main.route('/add_guest', methods=['POST'])
@login_required
@account_owner_required
def add_guest():
    """Create a guest user linked to current account owner"""
    email = (request.form.get('email') or '').strip().lower()
    name = (request.form.get('name') or '').strip()

    if not name or len(name) > _MAX_NAME_LEN:
        flash(f"Name must be between 1 and {_MAX_NAME_LEN} characters")
        return redirect(url_for('main.manage_guests'))
    if not email or len(email) > _MAX_EMAIL_LEN:
        flash(f"Email must be between 1 and {_MAX_EMAIL_LEN} characters")
        return redirect(url_for('main.manage_guests'))

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('A user with this email already exists')
        return redirect(url_for('main.manage_guests'))

    frontend_base = (current_app.config.get("FRONTEND_BASE_URL") or "").strip().rstrip("/")
    if not frontend_base:
        flash("FRONTEND_BASE_URL must be configured before inviting guest users")
        return redirect(url_for('main.manage_guests'))

    new_guest = User(
        email=email,
        name=name,
        password=generate_password_hash(secrets.token_urlsafe(48), method='scrypt'),
        admin=False,  # Guests are not admins
        is_global_admin=False,
        is_active=True,
        account_owner_id=current_user.id,
        owner_user_id=current_user.id,
        is_account_owner=False,
    )
    db.session.add(new_guest)
    db.session.commit()

    setup_url, expires_minutes = create_password_setup_link(new_guest)
    sent = send_password_setup_email(
        user_name=name,
        user_email=email,
        setup_url=setup_url,
        expires_minutes=expires_minutes,
    )
    if sent:
        flash(f"Guest invited. A password setup email was sent to {email}.")
    else:
        flash(
            "Guest created, but setup email could not be sent. "
            "Check global email settings and try again."
        )
    return redirect(url_for('main.manage_guests'))


@main.route('/guest_password')
@login_required
@account_owner_required
def guest_password_page():
    """Legacy route kept for backwards compatibility; new flow returns directly from add_guest."""
    return redirect(url_for('main.manage_guests'))


@main.route('/remove_guest/<int:guest_id>', methods=['POST'])
@login_required
@account_owner_required
def remove_guest(guest_id):
    """Remove a guest user (account owner only)"""
    guest = User.query.filter_by(id=int(guest_id), account_owner_id=current_user.id).first()

    if guest:
        db.session.query(PasswordSetupToken).filter_by(user_id=guest.id).delete()
        db.session.delete(guest)
        db.session.commit()
        flash('Guest user removed successfully')
    else:
        flash('Guest user not found or you do not have permission to remove them')

    return redirect(url_for('main.manage_guests'))


@main.route('/global_admin')
@login_required
@global_admin_required
def global_admin_panel():
    """Global admin can see all users and accounts"""
    all_users = User.query.limit(500).all()

    # Organize users by account owners
    account_owners = [u for u in all_users if u.account_owner_id is None and not u.is_global_admin]
    global_admins = [u for u in all_users if u.is_global_admin]
    standalone_users = [u for u in all_users if u.account_owner_id is None and not u.admin]

    return render_template('global_admin.html',
                         all_users=all_users,
                         account_owners=account_owners,
                         global_admins=global_admins,
                         standalone_users=standalone_users)


@main.route('/global_email_settings', methods=['GET', 'POST'])
@login_required
@global_admin_required
def global_email_settings():
    """Configure global email settings for all email notifications"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        smtp_server = request.form.get('smtp_server')

        # Check if global settings already exist
        settings = GlobalEmailSettings.query.first()

        if settings:
            # Update existing settings
            settings.email = email
            if password:
                settings.password = encrypt_password(password)
            settings.smtp_server = smtp_server
        else:
            # Create new settings
            settings = GlobalEmailSettings(
                id=1,  # Enforce single row
                email=email,
                password=encrypt_password(password),
                smtp_server=smtp_server
            )
            db.session.add(settings)

        db.session.commit()
        flash('Global email settings saved successfully')
        return redirect(url_for('main.settings'))

    return redirect(url_for('main.settings'))


@main.route('/ai_settings', methods=['POST'])
@login_required
@admin_required
@limiter.limit("12 per hour")
def ai_settings():
    """Save the user's OpenAI API key (encrypted) and optional model selection."""
    api_key_input = request.form.get('api_key', '').strip()
    model_input = request.form.get('model_version', '').strip()

    ai_config = AISettings.query.filter_by(user_id=current_user.id).first()

    if not api_key_input:
        if not ai_config or not ai_config.api_key:
            flash('API key cannot be empty', 'error')
            return redirect(url_for('main.settings'))
        # No new key provided but one is already stored — update model only
        if model_input:
            plaintext_key = decrypt_password(ai_config.api_key)
            valid, err = validate_model(plaintext_key, model_input)
            if not valid:
                flash(err, 'error')
                return redirect(url_for('main.settings'))
        ai_config.model_version = model_input or None
    else:
        if model_input:
            valid, err = validate_model(api_key_input, model_input)
            if not valid:
                flash(err, 'error')
                return redirect(url_for('main.settings'))
        encrypted_key = encrypt_password(api_key_input)
        if ai_config:
            ai_config.api_key = encrypted_key
            ai_config.model_version = model_input or None
        else:
            ai_config = AISettings(user_id=current_user.id, api_key=encrypted_key, model_version=model_input or None)
            db.session.add(ai_config)

    db.session.commit()
    flash('AI settings saved successfully')
    return redirect(url_for('main.settings'))


@main.route('/ai_settings/remove', methods=['POST'])
@login_required
@admin_required
def ai_settings_remove():
    """Remove the user's stored OpenAI API key and model so the configured
    DigitalOcean fallback (if any) is used instead."""
    ai_config = AISettings.query.filter_by(user_id=current_user.id).first()
    if not ai_config or not ai_config.api_key:
        flash('No API key is currently saved', 'error')
        return redirect(url_for('main.settings'))

    ai_config.api_key = None
    ai_config.model_version = None
    db.session.commit()
    flash('OpenAI API key removed')
    return redirect(url_for('main.settings'))


@main.route('/ai_insights', methods=['POST'])
@login_required
@admin_required
def ai_insights():
    """Query the configured AI provider for cash flow insights on demand and
    cache the result.  Limited to one refresh per user per 24 hours."""
    user_id = current_user.id

    ai_config = AISettings.query.filter_by(user_id=user_id).first()
    provider = select_provider(ai_config)
    if not provider:
        return Response(json.dumps({'error': 'No OpenAI API key configured. Please add one in Settings.'}),
                        status=400, mimetype='application/json')

    last_updated = ai_config.last_updated if ai_config else None
    cached_insights = ai_config.last_insights if ai_config else None
    if not is_refresh_due(last_updated):
        return Response(cached_insights or json.dumps({'insights': None}), status=200, mimetype='application/json')

    balance_record = Balance.query.filter_by(user_id=user_id).order_by(desc(Balance.date), desc(Balance.id)).first()
    current_balance = float(balance_record.amount) if balance_record else 0.0

    schedules = Schedule.query.filter_by(user_id=user_id).all()
    holds = Hold.query.filter_by(user_id=user_id).all()
    skips = Skip.query.filter_by(user_id=user_id).all()

    try:
        insights_json = fetch_insights_for_provider(provider, current_balance, schedules, holds, skips)
        insights_json, _parsed = normalize_and_validate_insights_json(insights_json)
    except AIProviderError as e:
        logger.warning("AI insights generation rejected for user %s: %s", user_id, e.original or e)
        return Response(json.dumps({'error': e.user_message}), status=502, mimetype='application/json')
    except AIInsightsFormatError as e:
        logger.warning("AI insights generation returned invalid payload for user %s: %s", user_id, e)
        return Response(json.dumps({'error': e.user_message}), status=502, mimetype='application/json')
    except Exception:
        logger.exception("AI insights generation failed for user %s", user_id)
        return Response(json.dumps({'error': 'An error occurred generating insights. Please try again later.'}), status=500, mimetype='application/json')

    if ai_config is None:
        ai_config = AISettings(user_id=user_id)
        db.session.add(ai_config)
    ai_config.last_insights = insights_json
    ai_config.last_updated = datetime.now(timezone.utc)
    db.session.commit()

    return Response(insights_json, status=200, mimetype='application/json')


@main.route('/manifest.json')
def serve_manifest():
    return send_file('manifest.json', mimetype='application/manifest+json')


@main.route('/sw.js')
def serve_sw():
    return send_file('sw.js', mimetype='application/javascript')


@main.route('/offline.html')
def serve_offline():
    return render_template('offline.html')


# ---------------------------------------------------------------------------
# 2FA – Setup (enable)
# ---------------------------------------------------------------------------

@main.route('/setup_2fa', methods=['GET'])
@login_required
def setup_2fa():
    """Show QR code and secret for the user to register in their authenticator app."""
    from flask import session as flask_session
    # Generate a fresh temp secret each time the setup page is (re-)loaded
    temp_secret = generate_totp_secret()
    flask_session['twofa_temp_secret'] = temp_secret

    qr_b64 = generate_qr_code_b64(temp_secret, current_user.email)
    return render_template('2fa_setup.html', qr_b64=qr_b64, secret=temp_secret)


@main.route('/setup_2fa', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def setup_2fa_post():
    """Verify the first TOTP code from the authenticator app and activate 2FA."""
    from flask import session as flask_session

    temp_secret = flask_session.get('twofa_temp_secret')
    if not temp_secret:
        flash('Session expired. Please restart the 2FA setup.')
        return redirect(url_for('main.setup_2fa'))

    code = request.form.get('code', '').strip()
    if not verify_totp(temp_secret, code):
        flash('Invalid code. Please try again.')
        return redirect(url_for('main.setup_2fa'))

    # Generate and persist backup codes
    plain_codes = generate_backup_codes()
    hashed_json = hash_backup_codes(plain_codes)

    user = User.query.get(current_user.id)
    user.twofa_enabled = True
    user.twofa_secret = encrypt_totp_secret(temp_secret)
    user.twofa_backup_codes = hashed_json
    db.session.commit()

    flask_session.pop('twofa_temp_secret', None)

    # Show backup codes exactly once
    from flask import session as flask_session
    flask_session['twofa_new_backup_codes'] = plain_codes
    return redirect(url_for('main.setup_2fa_backup_codes'))


@main.route('/setup_2fa/backup_codes')
@login_required
def setup_2fa_backup_codes():
    """Display backup codes once immediately after 2FA is enabled."""
    from flask import session as flask_session
    codes = flask_session.pop('twofa_new_backup_codes', None)
    if not codes:
        flash('Backup codes are only shown once, immediately after enabling 2FA.')
        return redirect(url_for('main.settings'))
    return render_template('2fa_backup_codes.html', codes=codes)


# ---------------------------------------------------------------------------
# 2FA – Disable
# ---------------------------------------------------------------------------

@main.route('/disable_2fa', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def disable_2fa():
    """
    Disable 2FA.  Requires the current account password AND a valid TOTP code
    (or backup code) as confirmation.
    """
    user = User.query.get(current_user.id)

    current_password = request.form.get('current_password', '').strip()
    totp_code = request.form.get('totp_code', '').strip()
    use_backup = request.form.get('use_backup')

    # 1. Verify password
    if not check_password_hash(user.password, current_password):
        flash('Incorrect password. 2FA was not disabled.')
        return redirect(url_for('main.settings'))

    # 2. Verify TOTP or backup code
    if use_backup:
        verified = verify_and_consume_backup_code(user, totp_code)
    else:
        if user.twofa_secret:
            plain_secret = decrypt_totp_secret(user.twofa_secret)
            verified = verify_totp(plain_secret, totp_code)
        else:
            verified = False

    if not verified:
        flash('Invalid verification code. 2FA was not disabled.')
        return redirect(url_for('main.settings'))

    user.twofa_enabled = False
    user.twofa_secret = None
    user.twofa_backup_codes = None
    db.session.commit()

    flash('Two-factor authentication has been disabled.')
    return redirect(url_for('main.settings'))
