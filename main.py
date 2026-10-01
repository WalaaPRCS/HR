from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from openpyxl import load_workbook
from openpyxl.utils.datetime import from_excel
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
MIGRATIONS_DIR = ROOT / "database" / "migrations"
COOKIE_NAME = "prcs_hr_session"
SESSION_HOURS = 8
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "db"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "prcs_hr"),
    "user": os.getenv("DB_USER", "prcs_hr_app"),
    "password": os.getenv("DB_PASSWORD", ""),
    "connect_timeout": 5,
}
ADMIN_USERNAME = os.getenv("HR_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("HR_ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() in ("1", "true", "yes")
LOGIN_FAILURES: dict[str, list[float]] = {}

if len(SESSION_SECRET) < 32:
    raise RuntimeError("Set a 32+ character SESSION_SECRET.")

def admin_setup_complete() -> bool:
    with connect() as conn:
        row = conn.execute("SELECT 1 FROM public.admin_account WHERE id = 1").fetchone()
    return row is not None

def get_admin_account():
    with connect() as conn:
        return conn.execute(
            "SELECT username, password_hash FROM public.admin_account WHERE id = 1"
        ).fetchone()

def password_hash(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt + digest).decode("ascii")

def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        raw = base64.b64decode(encoded_hash, validate=True)
        salt, expected = raw[:16], raw[16:]
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def connect():
    return psycopg.connect(**DB_CONFIG, row_factory=dict_row)


def prepare_database() -> None:
    last_error: Exception | None = None
    for _ in range(40):
        try:
            with connect() as conn:
                for migration in sorted(MIGRATIONS_DIR.glob("*.sql")):
                    conn.execute(migration.read_text(encoding="utf-8"))
            return
        except Exception as exc:
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"Database is not ready: {last_error}")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await asyncio.to_thread(prepare_database)
    yield


app = FastAPI(title="PRCS HR", docs_url=None, redoc_url=None, lifespan=lifespan)


def session_token(username: str, expires: int) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": username, "exp": expires}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def authenticated_username(request: Request) -> str | None:
    token = request.cookies.get(COOKIE_NAME, "")
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
        if int(claims["exp"]) <= int(time.time()):
            return None
        account = get_admin_account()
        if not account or not hmac.compare_digest(str(claims["sub"]), account["username"]):
            return None
        return str(claims["sub"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def check_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    expected = f"{scheme}://{host}".rstrip("/")
    if not hmac.compare_digest(origin.rstrip("/"), expected):
        raise HTTPException(status_code=403, detail="مصدر الطلب غير مسموح.")


@app.middleware("http")
async def protect_application(request: Request, call_next):
    path = request.url.path
    open_paths = {"/login.html", "/api/login", "/api/session", "/api/setup-status", "/api/setup-admin", "/api/healthz"}
    if path not in open_paths:
        if path.startswith("/api/") and path not in {"/api/setup-status", "/api/setup-admin"} and authenticated_username(request) is None:
            return JSONResponse(status_code=401, content={"detail": "يلزم تسجيل الدخول."})
        if not path.startswith("/api/") and authenticated_username(request) is None:
            return RedirectResponse("/login.html", status_code=303)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/healthz")
def healthz():
    try:
        with connect() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "database_unavailable"})


@app.get("/api/setup-status")
def setup_status():
    return {"setup_required": not admin_setup_complete()}


@app.post("/api/setup-admin")
async def setup_admin(request: Request):
    check_same_origin(request)
    if admin_setup_complete():
        raise HTTPException(status_code=409, detail="تم إنشاء حساب المدير مسبقاً.")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="بيانات إنشاء الحساب غير صالحة.")
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    confirmation = str(body.get("confirm_password", ""))
    if len(username) < 3 or len(username) > 80:
        raise HTTPException(status_code=422, detail="اسم المستخدم يجب أن يكون بين 3 و80 حرفاً.")
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(status_code=422, detail="كلمة المرور يجب أن تكون 12 حرفاً على الأقل.")
    if password != confirmation:
        raise HTTPException(status_code=422, detail="تأكيد كلمة المرور غير مطابق.")
    hashed = password_hash(password)
    try:
        with connect() as conn:
            conn.execute(
                "INSERT INTO public.admin_account (id, username, password_hash) VALUES (1, %s, %s)",
                (username, hashed),
            )
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="تم إنشاء حساب المدير مسبقاً.")
    response = JSONResponse({"authenticated": True, "username": username})
    response.set_cookie(
        COOKIE_NAME,
        session_token(username, int(time.time()) + SESSION_HOURS * 3600),
        max_age=SESSION_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response


@app.get("/api/session")
def get_session(request: Request):
    username = authenticated_username(request)
    return {"authenticated": bool(username), "username": username}


@app.post("/api/login")
async def login(request: Request):
    check_same_origin(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="بيانات تسجيل الدخول غير صالحة.")
    username = str(body.get("username", ""))[:200]
    password = str(body.get("password", ""))[:1000]
    client_ip = request.client.host if request.client else "unknown"
    bucket = f"{client_ip}:{username}"
    attempts = [stamp for stamp in LOGIN_FAILURES.get(bucket, []) if time.time() - stamp < 900]
    LOGIN_FAILURES[bucket] = attempts
    if len(attempts) >= 8:
        raise HTTPException(status_code=429, detail="محاولات كثيرة. حاول بعد 15 دقيقة.")
    account = get_admin_account()
    valid_user = bool(account and hmac.compare_digest(username.encode(), account["username"].encode()))
    valid_password = bool(account and verify_password(password, account["password_hash"]))
    if not (valid_user and valid_password):
        attempts.append(time.time())
        LOGIN_FAILURES[bucket] = attempts
        raise HTTPException(status_code=401, detail="اسم المستخدم أو كلمة المرور غير صحيحة.")
    LOGIN_FAILURES.pop(bucket, None)
    response = JSONResponse({"authenticated": True, "username": account["username"]})
    response.set_cookie(
        COOKIE_NAME,
        session_token(account["username"], int(time.time()) + SESSION_HOURS * 3600),
        max_age=SESSION_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/logout")
def logout(request: Request):
    check_same_origin(request)
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")
    return response


@app.get("/api/dashboard")
def dashboard():
    with connect() as conn:
        row = conn.execute(
            """
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE employment_status = 'على رأس عمله') AS active,
                   count(*) FILTER (WHERE project IS NOT NULL AND btrim(project) <> '') AS project_staff,
                   count(DISTINCT work_center) AS centers
            FROM public.employees
            """
        ).fetchone()
        directorates = conn.execute(
            """SELECT coalesce(nullif(btrim(directorate), ''), 'غير محدد') AS name, count(*) AS count
               FROM public.employees GROUP BY 1 ORDER BY count DESC, name LIMIT 12"""
        ).fetchall()
        cadre_types = conn.execute(
            """SELECT coalesce(nullif(btrim(cadre_type), ''), 'غير محدد') AS name, count(*) AS count
               FROM public.employees GROUP BY 1 ORDER BY count DESC, name LIMIT 10"""
        ).fetchall()
    return {"totals": row, "directorates": directorates, "cadre_types": cadre_types}


FILTER_COLUMNS = {
    "work_center": "work_center",
    "directorate": "directorate",
    "department": "department",
    "job_title": "job_title",
    "cadre_type": "cadre_type",
    "employment_status": "employment_status",
}


@app.get("/api/employee-options")
def employee_options(work_center: str = "", directorate: str = "", department: str = ""):
    dependencies = {
        "work_center": [],
        "directorate": [("work_center", work_center)],
        "department": [("work_center", work_center), ("directorate", directorate)],
        "job_title": [("directorate", directorate), ("department", department)],
        "cadre_type": [],
        "employment_status": [],
    }
    result: dict[str, list[str]] = {}
    with connect() as conn:
        for key, column in FILTER_COLUMNS.items():
            where_parts: list[str] = []
            params: list[str] = []
            for filter_column, value in dependencies[key]:
                if value:
                    where_parts.append(f"{filter_column} = %s")
                    params.append(value)
            where_sql = (" WHERE " + " AND ".join(where_parts) + " AND") if where_parts else " WHERE"
            rows = conn.execute(
                f"SELECT DISTINCT {column} AS value FROM public.employees{where_sql} {column} IS NOT NULL AND btrim({column}) <> ''",
                params,
            ).fetchall()
            result[key] = sorted((str(row["value"]) for row in rows), key=str.casefold)
    return result


@app.get("/api/employees")
def list_employees(
    q: str = "",
    work_center: str = "",
    directorate: str = "",
    department: str = "",
    job_title: str = "",
    cadre_type: str = "",
    employment_status: str = "",
    page: int = 1,
    page_size: int = 20,
):
    page = max(1, page)
    page_size = min(100, max(10, page_size))
    clauses: list[str] = []
    params: list[Any] = []
    if q.strip():
        clauses.append("(employee_number ILIKE %s OR employee_name ILIKE %s OR job_title ILIKE %s)")
        term = f"%{q.strip()}%"
        params.extend([term, term, term])
    for column, value in (
        ("work_center", work_center),
        ("directorate", directorate),
        ("department", department),
        ("job_title", job_title),
        ("cadre_type", cadre_type),
        ("employment_status", employment_status),
    ):
        if value.strip():
            clauses.append(f"{column} = %s")
            params.append(value.strip())
    where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with connect() as conn:
        total = conn.execute(
            f"SELECT count(*) AS total FROM public.employees{where_sql}", params
        ).fetchone()["total"]
        items = conn.execute(
            f"""SELECT employee_number, employee_name, work_center, directorate, department,
                       job_title, cadre_type, employment_status, project, grade
                FROM public.employees{where_sql}
                ORDER BY directorate NULLS LAST, employee_name
                LIMIT %s OFFSET %s""",
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@app.get("/api/import-status")
def import_status():
    with connect() as conn:
        state = conn.execute(
            """SELECT source_filename, imported_rows, imported_at
               FROM public.employee_import_control WHERE id = 1"""
        ).fetchone()
    return {"imported": bool(state), "record": state}


EXCEL_FIELDS = {
    "رقم الموظف": "employee_number",
    "اسم الموظف": "employee_name",
    "مركز العمل": "work_center",
    "الإدارة": "directorate",
    "القسم": "department",
    "المسمى الوظيفي": "job_title",
    "نوع الكادر": "cadre_type",
    "الحالة": "employment_status",
    "الراتب": "salary",
    "استحقاق الدرجة التالية": "next_grade_due_date",
    "نسبة التغطية": "coverage_percentage",
    "المشروع": "project",
    "الدرجة الوظيفية": "grade",
    "كود الموظف": "employee_code",
}
REQUIRED_COLUMNS = {
    "رقم الموظف", "اسم الموظف", "مركز العمل", "المسمى الوظيفي",
    "نوع الكادر", "الحالة", "كود الموظف",
}
INSERT_SQL = """
INSERT INTO public.employees (
    employee_number, employee_name, work_center, directorate, department, job_title,
    cadre_type, employment_status, salary, next_grade_due_date, coverage_percentage,
    project, grade, employee_code
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def clean_identifier(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return clean_text(value)


def clean_decimal(value: Any) -> Decimal | None:
    if value is None or str(value).strip() == "":
        return None
    if isinstance(value, (int, float, Decimal)):
        number = Decimal(str(value))
    else:
        text = str(value).strip().replace("٬", "").replace(",", "").translate(str.maketrans("٠١٢٣٤٥٦٧٨٩٫", "0123456789."))
        text = text.replace("%", "").replace(" ", "")
        text = re.sub(r"[^0-9.\-]", "", text)
        if not text:
            return None
        try:
            number = Decimal(text)
        except InvalidOperation:
            raise ValueError("قيمة رقمية غير صالحة.")
    if not number.is_finite():
        raise ValueError("قيمة رقمية غير صالحة.")
    return number


def clean_date(value: Any) -> date | None:
    if value is None or str(value).strip() == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, (int, float)):
        return from_excel(value).date()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(str(value).strip(), fmt).date()
        except ValueError:
            pass
    raise ValueError("صيغة تاريخ غير صالحة.")


def parse_employee_workbook(content: bytes) -> list[tuple[Any, ...]]:
    workbook = load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    sheet = workbook["الموظفون"] if "الموظفون" in workbook.sheetnames else workbook.active
    rows = sheet.iter_rows(values_only=True)
    try:
        header_row = next(rows)
    except StopIteration:
        raise HTTPException(status_code=422, detail="ملف Excel فارغ.")
    headers = {clean_text(value): index for index, value in enumerate(header_row) if clean_text(value)}
    missing = sorted(REQUIRED_COLUMNS - set(headers))
    if missing:
        raise HTTPException(status_code=422, detail={"message": "أعمدة أساسية مفقودة.", "columns": missing})

    data: list[tuple[Any, ...]] = []
    seen_numbers: set[str] = set()
    seen_codes: set[str] = set()
    errors: list[dict[str, Any]] = []
    for row_number, row in enumerate(rows, start=2):
        if not any(value is not None and str(value).strip() for value in row):
            continue
        source = {name: row[index] if index < len(row) else None for name, index in headers.items()}
        target: dict[str, Any] = {}
        for source_name, dest_name in EXCEL_FIELDS.items():
            value = source.get(source_name)
            try:
                if dest_name in ("employee_number", "employee_code"):
                    target[dest_name] = clean_identifier(value)
                elif dest_name in ("salary", "coverage_percentage"):
                    target[dest_name] = clean_decimal(value)
                elif dest_name == "next_grade_due_date":
                    target[dest_name] = clean_date(value)
                else:
                    target[dest_name] = clean_text(value)
            except (ValueError, InvalidOperation, OverflowError):
                errors.append({"row": row_number, "field": source_name})
        required_fields = ("employee_number", "employee_name", "work_center", "job_title", "cadre_type", "employment_status", "employee_code")
        missing_fields = [field for field in required_fields if not target.get(field)]
        if missing_fields:
            errors.append({"row": row_number, "field": "required"})
        number = target.get("employee_number")
        code = target.get("employee_code")
        if number and number in seen_numbers:
            errors.append({"row": row_number, "field": "duplicate_employee_number"})
        if code and code in seen_codes:
            errors.append({"row": row_number, "field": "duplicate_employee_code"})
        if number:
            seen_numbers.add(number)
        if code:
            seen_codes.add(code)
        if not missing_fields:
            data.append(tuple(target.get(EXCEL_FIELDS[header]) for header in EXCEL_FIELDS))
    workbook.close()
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "توجد أخطاء في الملف؛ لم يتم حفظ أي سجل.", "errors": errors[:50], "error_count": len(errors)},
        )
    if not data:
        raise HTTPException(status_code=422, detail="لم يتم العثور على سجلات موظفين صالحة في الملف.")
    return data


@app.post("/api/employees/import")
async def import_employees(request: Request, file: UploadFile = File(...)):
    check_same_origin(request)
    filename = Path(file.filename or "").name
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=415, detail="ارفع ملف Excel بصيغة .xlsx.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="حجم الملف أكبر من 16 ميجابايت.")
    if not content:
        raise HTTPException(status_code=400, detail="الملف فارغ.")
    try:
        rows = parse_employee_workbook(content)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=422, detail="تعذر قراءة ملف Excel. تأكد أنه ملف .xlsx سليم.")
    file_hash = hashlib.sha256(content).hexdigest()
    try:
        with connect() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (7210042026,))
            if conn.execute("SELECT id FROM public.employee_import_control WHERE id = 1").fetchone():
                raise HTTPException(status_code=409, detail="تم استيراد ملف الموظفين مسبقاً؛ الاستيراد متاح مرة واحدة فقط.")
            conn.executemany(INSERT_SQL, rows)
            conn.execute(
                """INSERT INTO public.employee_import_control
                   (id, source_filename, sha256, imported_rows, imported_by)
                   VALUES (1, %s, %s, %s, %s)""",
                (filename, file_hash, len(rows), ADMIN_USERNAME),
            )
    except HTTPException:
        raise
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="يوجد رقم موظف أو كود موظف مستخدم مسبقاً؛ تم التراجع عن الاستيراد بالكامل.")
    except psycopg.Error:
        raise HTTPException(status_code=500, detail="تعذر حفظ البيانات؛ تم التراجع عن الاستيراد بالكامل.")
    return {"ok": True, "imported_rows": len(rows), "source_filename": filename}


@app.get("/")
def root_page(request: Request):
    if authenticated_username(request) is None:
        return RedirectResponse("/login.html", status_code=303)
    return RedirectResponse("/index.html", status_code=307)


app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="public")
