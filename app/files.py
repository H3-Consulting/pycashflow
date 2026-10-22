from app import db
from datetime import datetime, date
import pandas as pd
import os
import logging
from natsort import index_natsorted
import numpy as np
from io import TextIOWrapper, StringIO
import csv
from .models import Schedule
import platform
from sqlalchemy import text

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB
ALLOWED_EXTENSIONS = {'.csv'}
ALLOWED_MIME_TYPES = {'text/csv', 'application/vnd.ms-excel', 'text/plain', 'application/csv'}


def export(user_id):
    """
    Export schedules for a specific user to CSV

    Args:
        user_id: The user ID to filter schedules
    """
    # Reuse the app's configured engine so export reads the same database as
    # the rest of the app (including the default app/data/db.sqlite path when
    # DATABASE_URL is unset).
    with db.engine.connect() as conn:
        # pull the schedule information for this user only
        df = pd.read_sql(text('SELECT * FROM schedule WHERE user_id = :uid'), conn, params={'uid': user_id})
    df = df.sort_values(by="startdate",
                        key=lambda x: np.argsort(index_natsorted(df["startdate"]))).reset_index(drop=True)

    def _sanitize_cell(value):
        """Prefix formula-triggering characters to prevent CSV injection."""
        s = str(value)
        if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
            return "'" + s
        return s

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Amount", "Type", "Frequency", "Next Date", "First Date"])
    for i in range(len(df.index)):
        writer.writerow([
            _sanitize_cell(df['name'][i]),
            _sanitize_cell(df['amount'][i]),
            _sanitize_cell(df['type'][i]),
            _sanitize_cell(df['frequency'][i]),
            _sanitize_cell(df['startdate'][i]),
            _sanitize_cell(df['firstdate'][i]),
        ])

    return output.getvalue()


def validate_upload(csv_file):
    """
    Validate a CSV upload before processing.
    Returns (True, None) on success or (False, error_message) on failure.
    """
    if csv_file is None or csv_file.filename == '':
        return False, "No file selected."

    _, ext = os.path.splitext(csv_file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file type '{ext}'. Only .csv files are accepted."

    mime = (csv_file.mimetype or '').lower().split(';')[0].strip()
    if mime and mime not in ALLOWED_MIME_TYPES:
        logger.warning("CSV upload rejected: unexpected MIME type '%s' for file '%s'", mime, csv_file.filename)
        return False, "Invalid file content type. Please upload a CSV file."

    # Check file size without fully reading into memory
    csv_file.seek(0, 2)  # seek to end
    size = csv_file.tell()
    csv_file.seek(0)  # rewind
    if size > MAX_UPLOAD_BYTES:
        return False, f"File too large ({size // 1024} KB). Maximum allowed size is {MAX_UPLOAD_BYTES // 1024} KB."

    return True, None


def upload(csv_file, user_id):
    """
    Upload CSV file and create/update schedules for a specific user.

    Args:
        csv_file: The CSV file to upload (werkzeug FileStorage)
        user_id: The user ID to assign schedules to
    Returns:
        (success_count, error_count)
    """
    valid, err = validate_upload(csv_file)
    if not valid:
        raise ValueError(err)

    valid_types = {"Income", "Expense"}
    valid_frequencies = {"Monthly", "Quarterly", "Yearly", "Weekly", "BiWeekly", "Onetime"}
    date_format = '%Y-%m-%d'
    success_count = 0
    error_count = 0

    wrapped = TextIOWrapper(csv_file, encoding='utf-8')
    csv_reader = csv.reader(wrapped, delimiter=',')
    next(csv_reader)  # skip header

    for row_num, row in enumerate(csv_reader, start=2):
        try:
            if len(row) < 6:
                logger.warning("CSV import row %d skipped: expected 6 columns, got %d", row_num, len(row))
                error_count += 1
                continue

            name = row[0].strip()
            if not name:
                logger.warning("CSV import row %d skipped: empty name", row_num)
                error_count += 1
                continue

            amount = float(row[1])
            row_type = row[2].strip()
            frequency = row[3].strip()
            next_date = datetime.strptime(row[4].strip(), date_format).date()
            first_date = datetime.strptime(row[5].strip(), date_format).date()

            if row_type not in valid_types:
                logger.warning("CSV import row %d skipped: invalid type '%s'", row_num, row_type)
                error_count += 1
                continue

            if frequency not in valid_frequencies:
                logger.warning("CSV import row %d skipped: invalid frequency '%s'", row_num, frequency)
                error_count += 1
                continue

            existing = Schedule.query.filter_by(name=name, user_id=user_id).first()
            if not existing:
                schedule = Schedule(name=name, amount=amount, type=row_type, frequency=frequency,
                                    startdate=next_date, firstdate=first_date, user_id=user_id)
                db.session.add(schedule)
            else:
                existing.amount = amount
                existing.frequency = frequency
                existing.startdate = next_date
                existing.type = row_type
                existing.firstdate = first_date
            db.session.commit()
            success_count += 1

        except (ValueError, IndexError) as exc:
            logger.warning("CSV import row %d skipped: %s", row_num, exc)
            error_count += 1
        except Exception as exc:
            logger.error("CSV import row %d unexpected error: %s", row_num, exc)
            error_count += 1

    return success_count, error_count


def version():
    # get current python version
    pyversion = platform.python_version()
    # Prefer Docker image tag when available; fall back to explicit APP_VERSION.
    docker_tag = os.environ.get("DOCKER_TAG", "").strip()
    app_version = os.environ.get("APP_VERSION", "").strip()
    resolved_version = docker_tag or app_version or "unknown"
    version = "pycashflow: " + resolved_version + " :: python: " + pyversion

    return version
