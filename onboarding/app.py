import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import google.auth
import requests
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from google.auth.transport.requests import AuthorizedSession


GOOGLE_ADS_SCOPE = "https://www.googleapis.com/auth/adwords"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


@dataclass(frozen=True)
class Settings:
  app_base_url: str
  oauth_client_id: str
  oauth_client_secret: str
  google_ads_developer_token: str
  state_signing_secret: str
  google_cloud_project: str
  google_ads_api_version: str = "v23"
  arba_project: str = ""
  arba_region: str = "us-central1"
  arba_job_name: str = "arba"
  arba_gcs_bucket: str = ""
  arba_gcs_object: str = "arba/google-ads.yaml"
  arba_google_ads_secret: str = "arba-google-ads-yaml"
  draft_secret_prefix: str = "arba-onboarding-draft-"
  write_secret_manager: bool = True
  write_gcs: bool = True
  update_cloud_run_job: bool = True
  run_arba_job_after_update: bool = False
  draft_ttl_seconds: int = 3600


def env_bool(name: str, default: bool) -> bool:
  value = os.getenv(name)
  if value is None:
    return default
  return value.strip().lower() in {"1", "true", "yes", "on"}


def get_settings() -> Settings:
  project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT") or ""
  return Settings(
    app_base_url=os.getenv("APP_BASE_URL", "http://localhost:8080").rstrip("/"),
    oauth_client_id=os.getenv("OAUTH_CLIENT_ID", ""),
    oauth_client_secret=os.getenv("OAUTH_CLIENT_SECRET", ""),
    google_ads_developer_token=os.getenv("GOOGLE_ADS_DEVELOPER_TOKEN", ""),
    state_signing_secret=os.getenv("STATE_SIGNING_SECRET", ""),
    google_cloud_project=project,
    google_ads_api_version=os.getenv("GOOGLE_ADS_API_VERSION", "v23"),
    arba_project=os.getenv("ARBA_PROJECT", project),
    arba_region=os.getenv("ARBA_REGION", "us-central1"),
    arba_job_name=os.getenv("ARBA_JOB_NAME", "arba"),
    arba_gcs_bucket=os.getenv("ARBA_GCS_BUCKET", os.getenv("ARBA_PROJECT", project)),
    arba_gcs_object=os.getenv("ARBA_GCS_OBJECT", "arba/google-ads.yaml"),
    arba_google_ads_secret=os.getenv(
      "ARBA_GOOGLE_ADS_SECRET", "arba-google-ads-yaml"
    ),
    draft_secret_prefix=os.getenv(
      "ARBA_DRAFT_SECRET_PREFIX", "arba-onboarding-draft-"
    ),
    write_secret_manager=env_bool("WRITE_SECRET_MANAGER", True),
    write_gcs=env_bool("WRITE_GCS", True),
    update_cloud_run_job=env_bool("UPDATE_CLOUD_RUN_JOB", True),
    run_arba_job_after_update=env_bool("RUN_ARBA_JOB_AFTER_UPDATE", False),
    draft_ttl_seconds=int(os.getenv("DRAFT_TTL_SECONDS", "3600")),
  )


def require_config(settings: Settings) -> None:
  missing = [
    name
    for name, value in {
      "APP_BASE_URL": settings.app_base_url,
      "OAUTH_CLIENT_ID": settings.oauth_client_id,
      "OAUTH_CLIENT_SECRET": settings.oauth_client_secret,
      "GOOGLE_ADS_DEVELOPER_TOKEN": settings.google_ads_developer_token,
      "STATE_SIGNING_SECRET": settings.state_signing_secret,
      "GOOGLE_CLOUD_PROJECT": settings.google_cloud_project,
    }.items()
    if not value
  ]
  if missing:
    raise HTTPException(
      status_code=500,
      detail=f"Missing required environment variables: {', '.join(missing)}",
    )


def b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
  padding = "=" * (-len(value) % 4)
  return base64.urlsafe_b64decode(value + padding)


def sign(payload: str, secret: str) -> str:
  digest = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
  return b64url(digest)


def make_state(data: dict[str, Any], secret: str) -> str:
  payload = b64url(json.dumps(data, separators=(",", ":")).encode())
  return f"{payload}.{sign(payload, secret)}"


def read_state(state: str, secret: str) -> dict[str, Any]:
  try:
    payload, signature = state.split(".", 1)
  except ValueError as exc:
    raise HTTPException(status_code=400, detail="Invalid OAuth state") from exc
  expected = sign(payload, secret)
  if not hmac.compare_digest(signature, expected):
    raise HTTPException(status_code=400, detail="Invalid OAuth state signature")
  data = json.loads(b64url_decode(payload))
  if int(data.get("exp", 0)) < int(time.time()):
    raise HTTPException(status_code=400, detail="OAuth state expired")
  return data


def google_ads_headers(access_token: str, login_customer_id: str | None = None) -> dict[str, str]:
  settings = get_settings()
  headers = {
    "Authorization": f"Bearer {access_token}",
    "developer-token": settings.google_ads_developer_token,
    "Content-Type": "application/json",
  }
  if login_customer_id:
    headers["login-customer-id"] = login_customer_id
  return headers


def google_ads_url(path: str) -> str:
  settings = get_settings()
  return f"https://googleads.googleapis.com/{settings.google_ads_api_version}/{path.lstrip('/')}"


def exchange_code_for_token(code: str) -> dict[str, Any]:
  settings = get_settings()
  response = requests.post(
    "https://oauth2.googleapis.com/token",
    data={
      "code": code,
      "client_id": settings.oauth_client_id,
      "client_secret": settings.oauth_client_secret,
      "redirect_uri": callback_url(settings),
      "grant_type": "authorization_code",
    },
    timeout=60,
  )
  if not response.ok:
    raise HTTPException(status_code=400, detail=f"OAuth token exchange failed: {response.text}")
  token = response.json()
  if not token.get("refresh_token"):
    raise HTTPException(
      status_code=400,
      detail=(
        "Google did not return a refresh token. Reconnect with consent, "
        "or remove the existing app grant and try again."
      ),
    )
  return token


def list_accessible_customer_ids(access_token: str) -> list[str]:
  response = requests.get(
    google_ads_url("customers:listAccessibleCustomers"),
    headers=google_ads_headers(access_token),
    timeout=60,
  )
  if not response.ok:
    raise HTTPException(
      status_code=400,
      detail=f"Failed to list accessible Google Ads customers: {response.text}",
    )
  resource_names = response.json().get("resourceNames", [])
  return [resource.split("/", 1)[1] for resource in resource_names]


def search_customer_clients(access_token: str, login_customer_id: str) -> list[dict[str, Any]]:
  query = """
    SELECT
      customer_client.client_customer,
      customer_client.descriptive_name,
      customer_client.id,
      customer_client.level,
      customer_client.manager,
      customer_client.status
    FROM customer_client
    WHERE customer_client.status != 'CANCELED'
  """
  response = requests.post(
    google_ads_url(f"customers/{login_customer_id}/googleAds:searchStream"),
    headers=google_ads_headers(access_token, login_customer_id),
    json={"query": query},
    timeout=120,
  )
  if not response.ok:
    return []
  rows: list[dict[str, Any]] = []
  for chunk in response.json():
    for result in chunk.get("results", []):
      client = result.get("customerClient", {})
      customer_id = str(client.get("id") or "").replace("-", "")
      if customer_id:
        rows.append(
          {
            "id": customer_id,
            "name": client.get("descriptiveName") or customer_id,
            "manager": bool(client.get("manager")),
            "level": int(client.get("level", 0)),
            "status": client.get("status", "UNKNOWN"),
            "login_customer_id": login_customer_id,
          }
        )
  return rows


def discover_accounts(access_token: str) -> list[dict[str, Any]]:
  accessible_ids = list_accessible_customer_ids(access_token)
  accounts_by_id: dict[str, dict[str, Any]] = {}
  for customer_id in accessible_ids:
    accounts_by_id.setdefault(
      customer_id,
      {
        "id": customer_id,
        "name": customer_id,
        "manager": False,
        "level": 0,
        "status": "ACCESSIBLE",
        "login_customer_id": "",
      },
    )
    for child in search_customer_clients(access_token, customer_id):
      existing = accounts_by_id.get(child["id"])
      if not existing or child.get("level", 99) < existing.get("level", 99):
        accounts_by_id[child["id"]] = child
  return sorted(
    accounts_by_id.values(),
    key=lambda account: (not account.get("manager", False), account.get("name", ""), account["id"]),
  )


def make_yaml(refresh_token: str, login_customer_id: str | None) -> str:
  settings = get_settings()
  lines = [
    f"developer_token: {settings.google_ads_developer_token}",
    f"client_id: {settings.oauth_client_id}",
    f"client_secret: {settings.oauth_client_secret}",
    f"refresh_token: {refresh_token}",
    "use_proto_plus: True",
  ]
  if login_customer_id:
    lines.append(f"login_customer_id: {login_customer_id}")
  return "\n".join(lines) + "\n"


def authorized_session() -> AuthorizedSession:
  credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
  return AuthorizedSession(credentials)


def ensure_secret(session: AuthorizedSession, project: str, secret_id: str) -> None:
  parent = f"projects/{project}"
  name = f"{parent}/secrets/{secret_id}"
  get_response = session.get(f"https://secretmanager.googleapis.com/v1/{name}")
  if get_response.status_code == 200:
    return
  if get_response.status_code != 404:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to inspect Secret Manager secret {secret_id}: {get_response.text}",
    )
  create_response = session.post(
    f"https://secretmanager.googleapis.com/v1/{parent}/secrets?secretId={secret_id}",
    json={"replication": {"automatic": {}}},
  )
  if create_response.status_code not in {200, 201}:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to create Secret Manager secret {secret_id}: {create_response.text}",
    )


def put_secret(project: str, secret_id: str, value: str) -> None:
  session = authorized_session()
  ensure_secret(session, project, secret_id)
  payload = base64.b64encode(value.encode()).decode("ascii")
  response = session.post(
    f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret_id}:addVersion",
    json={"payload": {"data": payload}},
  )
  if response.status_code not in {200, 201}:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to write Secret Manager secret {secret_id}: {response.text}",
    )


def delete_secret(project: str, secret_id: str) -> None:
  session = authorized_session()
  response = session.delete(
    f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret_id}"
  )
  if response.status_code not in {200, 404}:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to delete onboarding draft {secret_id}: {response.text}",
    )


def access_secret(project: str, secret_id: str) -> str:
  session = authorized_session()
  response = session.get(
    f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret_id}/versions/latest:access"
  )
  if response.status_code != 200:
    raise HTTPException(
      status_code=400,
      detail=f"Failed to read onboarding draft: {response.text}",
    )
  payload = response.json()["payload"]["data"]
  return base64.b64decode(payload).decode()


def upload_to_gcs(bucket_name: str, object_name: str, value: str) -> str:
  from google.cloud import storage

  client = storage.Client()
  bucket = client.bucket(bucket_name)
  blob = bucket.blob(object_name)
  blob.upload_from_string(value, content_type="text/plain")
  return f"gs://{bucket_name}/{object_name}"


def update_cloud_run_job_env(project: str, region: str, job_name: str, env_vars: dict[str, str]) -> None:
  session = authorized_session()
  resource_name = f"projects/{project}/locations/{region}/jobs/{job_name}"
  url = f"https://run.googleapis.com/v2/{resource_name}"
  response = session.get(url)
  if response.status_code != 200:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to read Cloud Run job {job_name}: {response.text}",
    )
  job = response.json()
  containers = job.setdefault("template", {}).setdefault("template", {}).setdefault("containers", [])
  if not containers:
    raise HTTPException(status_code=500, detail=f"Cloud Run job {job_name} has no containers")
  env = containers[0].setdefault("env", [])
  by_name = {item["name"]: item for item in env if "name" in item}
  for name, value in env_vars.items():
    if name in by_name:
      by_name[name]["value"] = value
    else:
      env.append({"name": name, "value": value})
  body = {"template": {"template": {"containers": containers}}}
  patch_response = session.patch(
    f"{url}?updateMask=template.template.containers",
    json=body,
  )
  if patch_response.status_code not in {200, 201}:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to update Cloud Run job {job_name}: {patch_response.text}",
    )


def run_cloud_run_job(project: str, region: str, job_name: str) -> str:
  session = authorized_session()
  resource_name = f"projects/{project}/locations/{region}/jobs/{job_name}"
  response = session.post(f"https://run.googleapis.com/v2/{resource_name}:run")
  if response.status_code not in {200, 201}:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to start Cloud Run job {job_name}: {response.text}",
    )
  return response.json().get("name", "started")


def callback_url(settings: Settings) -> str:
  return f"{settings.app_base_url}/oauth/callback"


def render_page(title: str, body: str) -> HTMLResponse:
  return HTMLResponse(
    f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Inter, Arial, sans-serif; margin: 32px; color: #1f2937; }}
    main {{ max-width: 920px; margin: 0 auto; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 20px; margin: 16px 0; }}
    .row {{ display: flex; align-items: start; gap: 10px; padding: 8px 0; border-bottom: 1px solid #f3f4f6; }}
    .row:last-child {{ border-bottom: 0; }}
    .muted {{ color: #6b7280; font-size: 14px; }}
    .badge {{ display: inline-block; border: 1px solid #d1d5db; border-radius: 999px; padding: 2px 8px; font-size: 12px; margin-left: 8px; }}
    button, .button {{ background: #2563eb; border: 0; border-radius: 6px; color: white; padding: 10px 14px; text-decoration: none; cursor: pointer; }}
    select, input[type=text] {{ width: 100%; padding: 8px; margin-top: 4px; }}
    label {{ display: block; margin: 12px 0 6px; }}
  </style>
</head>
<body>
<main>
  {body}
</main>
</body>
</html>"""
  )


app = FastAPI(title="ARBA OAuth Onboarding")


@app.get("/healthz")
def healthz() -> dict[str, str]:
  return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
  body = """
    <h1>ARBA Google Ads onboarding</h1>
    <p>Connect a Google Ads user, choose accounts, and update ARBA credentials.</p>
    <p><a class="button" href="/connect">Connect Google Ads</a></p>
  """
  return render_page("ARBA onboarding", body)


@app.get("/connect")
def connect() -> RedirectResponse:
  settings = get_settings()
  require_config(settings)
  now = int(time.time())
  state = make_state(
    {"nonce": secrets.token_hex(16), "iat": now, "exp": now + 600},
    settings.state_signing_secret,
  )
  params = urlencode(
    {
      "client_id": settings.oauth_client_id,
      "redirect_uri": callback_url(settings),
      "response_type": "code",
      "scope": GOOGLE_ADS_SCOPE,
      "access_type": "offline",
      "prompt": "consent",
      "include_granted_scopes": "false",
      "state": state,
    }
  )
  return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@app.get("/oauth/callback", response_class=HTMLResponse)
def oauth_callback(code: str | None = None, state: str | None = None, error: str | None = None) -> HTMLResponse:
  settings = get_settings()
  require_config(settings)
  if error:
    raise HTTPException(status_code=400, detail=f"OAuth failed: {error}")
  if not code or not state:
    raise HTTPException(status_code=400, detail="OAuth callback is missing code or state")
  read_state(state, settings.state_signing_secret)
  token = exchange_code_for_token(code)
  accounts = discover_accounts(token["access_token"])
  draft_id = f"{settings.draft_secret_prefix}{secrets.token_hex(12)}"
  draft = {
    "created_at": int(time.time()),
    "expires_at": int(time.time()) + settings.draft_ttl_seconds,
    "refresh_token": token["refresh_token"],
    "accounts": accounts,
  }
  put_secret(settings.google_cloud_project, draft_id, json.dumps(draft))
  return render_account_form(draft_id, accounts)


def render_account_form(draft_id: str, accounts: list[dict[str, Any]]) -> HTMLResponse:
  login_options = ['<option value="">Direct access / no MCC login customer</option>']
  for account in accounts:
    if account.get("manager"):
      account_id = html.escape(account["id"])
      account_name = html.escape(account["name"])
      login_options.append(
        f'<option value="{account_id}">{account_name} ({account_id})</option>'
      )
  account_rows = []
  for account in accounts:
    if account.get("manager"):
      continue
    label = f'{account["name"]} ({account["id"]})'
    account_id = html.escape(account["id"])
    account_status = html.escape(account.get("status", "UNKNOWN"))
    account_source = html.escape(account.get("login_customer_id") or "direct access")
    account_rows.append(
      f"""
      <div class="row">
        <input type="checkbox" name="account_ids" value="{account_id}" id="account-{account_id}">
        <label for="account-{account_id}">
          {html.escape(label)}
          <span class="badge">{account_status}</span>
          <div class="muted">Discovered via {account_source}</div>
        </label>
      </div>
      """
    )
  body = f"""
    <h1>Select Google Ads accounts</h1>
    <p class="muted">The refresh token is stored as a temporary onboarding draft in Secret Manager.</p>
    <form method="post" action="/configure">
      <input type="hidden" name="draft_id" value="{html.escape(draft_id)}">
      <label for="login_customer_id">MCC / login customer</label>
      <select id="login_customer_id" name="login_customer_id">
        {''.join(login_options)}
      </select>
      <div class="card">
        <h2>Accounts</h2>
        {''.join(account_rows) if account_rows else '<p>No non-manager accounts found.</p>'}
      </div>
      <label>
        <input type="checkbox" name="run_job_update" value="true" checked>
        Update target ARBA Cloud Run job
      </label>
      <button type="submit">Save ARBA credentials</button>
    </form>
  """
  return render_page("Select accounts", body)


@app.post("/configure", response_class=HTMLResponse)
def configure(
  draft_id: str = Form(...),
  login_customer_id: str = Form(""),
  account_ids: list[str] | None = Form(default=None),
  run_job_update: str | None = Form(default=None),
) -> HTMLResponse:
  settings = get_settings()
  require_config(settings)
  if not draft_id.startswith(settings.draft_secret_prefix):
    raise HTTPException(status_code=400, detail="Invalid draft id")
  account_ids = [account_id.strip().replace("-", "") for account_id in account_ids or []]
  if not account_ids:
    raise HTTPException(status_code=400, detail="Select at least one account")

  draft = json.loads(access_secret(settings.google_cloud_project, draft_id))
  if int(draft.get("expires_at", 0)) < int(time.time()):
    delete_secret(settings.google_cloud_project, draft_id)
    raise HTTPException(status_code=400, detail="Onboarding draft expired. Connect again.")

  known_ids = {account["id"] for account in draft.get("accounts", [])}
  unknown = sorted(set(account_ids) - known_ids)
  if unknown:
    raise HTTPException(status_code=400, detail=f"Unknown account ids: {', '.join(unknown)}")

  login_customer_id = login_customer_id.strip().replace("-", "")
  yaml_text = make_yaml(draft["refresh_token"], login_customer_id or None)
  storage_actions: list[str] = []

  if settings.write_secret_manager:
    put_secret(settings.arba_project, settings.arba_google_ads_secret, yaml_text)
    storage_actions.append(
      f"Secret Manager: {settings.arba_project}/{settings.arba_google_ads_secret}"
    )

  ads_config = ""
  if settings.write_gcs:
    if not settings.arba_gcs_bucket:
      raise HTTPException(status_code=500, detail="ARBA_GCS_BUCKET is required when WRITE_GCS=true")
    ads_config = upload_to_gcs(settings.arba_gcs_bucket, settings.arba_gcs_object, yaml_text)
    storage_actions.append(f"GCS: {ads_config}")

  update_requested = bool(run_job_update) and settings.update_cloud_run_job
  if update_requested:
    env_vars = {"ACCOUNT": ",".join(account_ids)}
    if ads_config:
      env_vars["ADS_CONFIG"] = ads_config
    update_cloud_run_job_env(
      settings.arba_project,
      settings.arba_region,
      settings.arba_job_name,
      env_vars,
    )
    storage_actions.append(
      f"Cloud Run job updated: {settings.arba_project}/{settings.arba_region}/{settings.arba_job_name}"
    )

  if update_requested and settings.run_arba_job_after_update:
    operation_name = run_cloud_run_job(
      settings.arba_project,
      settings.arba_region,
      settings.arba_job_name,
    )
    storage_actions.append(f"Cloud Run job started: {operation_name}")

  delete_secret(settings.google_cloud_project, draft_id)

  safe_login = login_customer_id or "direct access"
  body = f"""
    <h1>ARBA credentials saved</h1>
    <div class="card">
      <p><strong>Login customer:</strong> {html.escape(safe_login)}</p>
      <p><strong>Accounts:</strong> {html.escape(", ".join(account_ids))}</p>
      <p><strong>Actions:</strong></p>
      <ul>{''.join(f'<li>{html.escape(action)}</li>' for action in storage_actions)}</ul>
    </div>
    <p class="muted">The YAML content and refresh token are not displayed.</p>
  """
  return render_page("Credentials saved", body)
