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
      child_level = child.get("level", 99)
      existing_level = existing.get("level", 99) if existing else 99
      if (
        not existing
        or child_level < existing_level
        or (
          child_level == existing_level
          and child.get("manager", False)
          and not existing.get("manager", False)
        )
      ):
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


def wait_for_operation(
  session: AuthorizedSession,
  operation: dict[str, Any],
  action: str,
  timeout_seconds: int = 120,
) -> None:
  deadline = time.monotonic() + timeout_seconds
  current = operation
  while True:
    if current.get("done"):
      if error := current.get("error"):
        raise HTTPException(
          status_code=500,
          detail=f"Failed to {action}: {json.dumps(error)}",
        )
      return
    operation_name = current.get("name")
    if not operation_name:
      raise HTTPException(
        status_code=500,
        detail=f"Failed to {action}: Cloud Run returned no operation name",
      )
    if time.monotonic() >= deadline:
      raise HTTPException(
        status_code=504,
        detail=f"Timed out waiting to {action}",
      )
    time.sleep(1)
    response = session.get(f"https://run.googleapis.com/v2/{operation_name}")
    if response.status_code != 200:
      raise HTTPException(
        status_code=500,
        detail=f"Failed to check {action}: {response.text}",
      )
    current = response.json()


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
  patch_response = session.patch(url, json=job)
  if patch_response.status_code not in {200, 201}:
    raise HTTPException(
      status_code=500,
      detail=f"Failed to update Cloud Run job {job_name}: {patch_response.text}",
    )
  wait_for_operation(
    session,
    patch_response.json(),
    f"update Cloud Run job {job_name}",
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
    * {{ box-sizing: border-box; letter-spacing: 0; }}
    body {{ min-height: 100vh; margin: 0; background: #f6f7f9; color: #202124; font-family: Inter, Arial, sans-serif; }}
    main {{ width: min(680px, calc(100% - 32px)); margin: 56px auto; padding: 32px; background: #fff; border: 1px solid #e0e3e7; border-radius: 8px; box-shadow: 0 8px 28px rgba(32, 33, 36, 0.08); }}
    .brand {{ margin-bottom: 28px; color: #5f6368; font-size: 13px; font-weight: 700; text-transform: uppercase; }}
    h1 {{ margin: 0 0 10px; font-size: 28px; line-height: 1.25; }}
    h2 {{ margin: 0 0 12px; font-size: 18px; }}
    p {{ line-height: 1.55; }}
    form {{ margin-top: 24px; }}
    .card {{ border: 1px solid #dfe3e8; border-radius: 8px; padding: 18px; margin: 18px 0; background: #fff; }}
    .row {{ display: flex; align-items: center; gap: 12px; min-height: 48px; padding: 10px 8px; border-bottom: 1px solid #edf0f2; transition: background 120ms ease; }}
    .row:last-child {{ border-bottom: 0; }}
    .row:hover {{ background: #f8fafd; }}
    .row input {{ flex: 0 0 auto; width: 17px; height: 17px; accent-color: #1a73e8; }}
    .row label {{ flex: 1; margin: 0; cursor: pointer; line-height: 1.4; }}
    .muted {{ color: #6b7280; font-size: 14px; }}
    .badge {{ display: inline-block; margin-left: 8px; padding: 2px 7px; border: 1px solid #b9dfc6; border-radius: 999px; background: #edf7f0; color: #137333; font-size: 11px; }}
    .mode-switch {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 3px; border: 1px solid #dfe3e8; border-radius: 8px; background: #f1f3f4; margin: 20px 0 24px; }}
    .mode-option {{ margin: 0; position: relative; }}
    .mode-option input {{ position: absolute; opacity: 0; pointer-events: none; }}
    .mode-option span {{ display: block; min-height: 42px; padding: 11px 14px; border-radius: 6px; text-align: center; cursor: pointer; color: #5f6368; }}
    .mode-option input:checked + span {{ background: #fff; color: #174ea6; font-weight: 600; box-shadow: 0 1px 3px rgba(32, 33, 36, 0.16); }}
    .mode-option input:focus-visible + span {{ outline: 2px solid #1a73e8; outline-offset: 1px; }}
    .account-group + .account-group {{ margin-top: 20px; }}
    .account-group h3 {{ margin: 0 8px 6px; color: #5f6368; font-size: 13px; font-weight: 600; }}
    button, .button {{ display: inline-flex; align-items: center; justify-content: center; min-height: 42px; padding: 10px 18px; border: 0; border-radius: 6px; background: #1a73e8; color: white; font-weight: 600; text-decoration: none; cursor: pointer; transition: background 120ms ease, box-shadow 120ms ease; }}
    form > button {{ margin-top: 18px; }}
    button:hover, .button:hover {{ background: #1765cc; box-shadow: 0 2px 6px rgba(26, 115, 232, 0.24); }}
    button:focus-visible, .button:focus-visible {{ outline: 3px solid rgba(26, 115, 232, 0.3); outline-offset: 2px; }}
    select, input[type=text] {{ width: 100%; min-height: 44px; padding: 9px 11px; margin-top: 6px; border: 1px solid #bdc1c6; border-radius: 6px; background: #fff; color: #202124; font: inherit; }}
    select:focus, input[type=text]:focus {{ border-color: #1a73e8; outline: 2px solid rgba(26, 115, 232, 0.16); }}
    label {{ display: block; margin: 12px 0 6px; }}
    [hidden] {{ display: none !important; }}
    @media (max-width: 560px) {{
      main {{ width: 100%; min-height: 100vh; margin: 0; padding: 28px 20px; border: 0; border-radius: 0; box-shadow: none; }}
      h1 {{ font-size: 25px; }}
      .mode-option span {{ padding-inline: 8px; }}
      button, .button {{ width: 100%; }}
    }}
  </style>
</head>
<body>
<main>
  <div class="brand">ARBA</div>
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
    <h1>Connect Google Ads</h1>
    <p class="muted">Sign in and choose the advertising data to include in ARBA.</p>
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
  managers = [account for account in accounts if account.get("manager")]
  clients = [account for account in accounts if not account.get("manager")]
  account_names = {account["id"]: account["name"] for account in accounts}

  manager_options = []
  for manager in managers:
    manager_id = html.escape(manager["id"])
    manager_name = html.escape(manager["name"])
    manager_options.append(
      f'<option value="{manager_id}">{manager_name} ({manager_id})</option>'
    )

  grouped_clients: dict[str, list[dict[str, Any]]] = {}
  for account in clients:
    grouped_clients.setdefault(account.get("login_customer_id") or "", []).append(account)

  account_groups = []
  for source_id, group in grouped_clients.items():
    if source_id:
      source_name = account_names.get(source_id, source_id)
      group_title = f"Accounts under {source_name}"
    else:
      group_title = "Available accounts"
    rows = []
    for account in group:
      account_id = html.escape(account["id"])
      account_name = html.escape(account["name"])
      account_status = html.escape(account.get("status", "UNKNOWN"))
      rows.append(
        f"""
        <div class="row">
          <input type="checkbox" name="account_ids" value="{account_id}" id="account-{account_id}">
          <label for="account-{account_id}">
            {account_name} ({account_id})
            <span class="badge">{account_status}</span>
          </label>
        </div>
        """
      )
    account_groups.append(
      f'<div class="account-group"><h3>{html.escape(group_title)}</h3>{"".join(rows)}</div>'
    )

  has_managers = bool(manager_options)
  has_clients = bool(account_groups)
  if has_managers and has_clients:
    mode_selector = """
    <div class="mode-switch">
      <label class="mode-option">
        <input type="radio" name="target_type" value="manager" checked>
        <span>MCC</span>
      </label>
      <label class="mode-option">
        <input type="radio" name="target_type" value="accounts">
        <span>Accounts</span>
      </label>
    </div>
    """
  elif has_managers:
    mode_selector = '<input type="hidden" name="target_type" value="manager">'
  else:
    mode_selector = '<input type="hidden" name="target_type" value="accounts">'
  body = f"""
    <h1>Choose what to analyze</h1>
    <form method="post" action="/configure">
      <input type="hidden" name="draft_id" value="{html.escape(draft_id)}">
      {mode_selector}
      <div id="manager-section" {'' if has_managers else 'hidden'}>
        <label for="manager_id">MCC account</label>
        <select id="manager_id" name="manager_id" {'required' if has_managers else 'disabled'}>
          {''.join(manager_options)}
        </select>
      </div>
      <div id="accounts-section" class="card" {'hidden' if has_managers else ''}>
        {''.join(account_groups) if account_groups else '<p>No individual accounts found.</p>'}
      </div>
      <button type="submit">Continue</button>
    </form>
    <script>
      const radios = document.querySelectorAll('input[name="target_type"]');
      const managerSection = document.getElementById('manager-section');
      const accountsSection = document.getElementById('accounts-section');
      const managerSelect = document.getElementById('manager_id');
      const accountInputs = accountsSection.querySelectorAll('input[name="account_ids"]');
      const form = document.querySelector('form');

      function selectedTargetType() {{
        const selected = document.querySelector('input[name="target_type"]:checked');
        const hidden = document.querySelector('input[name="target_type"][type="hidden"]');
        return selected ? selected.value : hidden.value;
      }}

      function syncMode() {{
        const managerMode = selectedTargetType() === 'manager';
        managerSection.hidden = !managerMode;
        accountsSection.hidden = managerMode;
        if (managerSelect) {{
          managerSelect.disabled = !managerMode;
          managerSelect.required = managerMode;
        }}
        accountInputs.forEach((input) => {{ input.disabled = managerMode; }});
      }}

      radios.forEach((radio) => radio.addEventListener('change', syncMode));
      accountInputs.forEach((input) => input.addEventListener('change', () => {{
        accountInputs.forEach((item) => item.setCustomValidity(''));
      }}));
      form.addEventListener('submit', (event) => {{
        const accountMode = selectedTargetType() === 'accounts';
        if (accountMode && accountInputs.length && !Array.from(accountInputs).some((input) => input.checked)) {{
          event.preventDefault();
          accountInputs[0].setCustomValidity('Select at least one account');
          accountInputs[0].reportValidity();
        }}
      }});
      syncMode();
    </script>
  """
  return render_page("Select accounts", body)


def resolve_target(
  accounts: list[dict[str, Any]],
  target_type: str,
  manager_id: str,
  account_ids: list[str] | None,
) -> tuple[list[str], str | None, str, str]:
  accounts_by_id = {account["id"]: account for account in accounts}
  manager_id = manager_id.strip().replace("-", "")
  selected_ids = list(
    dict.fromkeys(account_id.strip().replace("-", "") for account_id in account_ids or [])
  )

  if target_type == "manager":
    manager = accounts_by_id.get(manager_id)
    if not manager or not manager.get("manager"):
      raise HTTPException(status_code=400, detail="Select an available manager account")
    login_customer_id = manager.get("login_customer_id") or manager_id
    label = f'{manager["name"]} ({manager_id})'
    return [manager_id], login_customer_id, "MCC", label

  if target_type != "accounts":
    raise HTTPException(status_code=400, detail="Unknown account selection type")
  if not selected_ids:
    raise HTTPException(status_code=400, detail="Select at least one account")

  selected_accounts = []
  for account_id in selected_ids:
    account = accounts_by_id.get(account_id)
    if not account or account.get("manager"):
      raise HTTPException(status_code=400, detail=f"Unknown account: {account_id}")
    selected_accounts.append(account)

  login_customer_ids = {
    account.get("login_customer_id") or "" for account in selected_accounts
  }
  if len(login_customer_ids) > 1:
    raise HTTPException(
      status_code=400,
      detail="Selected accounts belong to different MCCs. Choose accounts from one MCC.",
    )
  login_customer_id = next(iter(login_customer_ids)) or None
  labels = ", ".join(
    f'{account["name"]} ({account["id"]})' for account in selected_accounts
  )
  return selected_ids, login_customer_id, "Accounts", labels


@app.post("/configure", response_class=HTMLResponse)
def configure(
  draft_id: str = Form(...),
  target_type: str = Form(...),
  manager_id: str = Form(""),
  account_ids: list[str] | None = Form(default=None),
) -> HTMLResponse:
  settings = get_settings()
  require_config(settings)
  if not draft_id.startswith(settings.draft_secret_prefix):
    raise HTTPException(status_code=400, detail="Invalid draft id")
  draft = json.loads(access_secret(settings.google_cloud_project, draft_id))
  if int(draft.get("expires_at", 0)) < int(time.time()):
    delete_secret(settings.google_cloud_project, draft_id)
    raise HTTPException(status_code=400, detail="Onboarding draft expired. Connect again.")

  selected_ids, login_customer_id, selection_type, selection_label = resolve_target(
    draft.get("accounts", []), target_type, manager_id, account_ids
  )
  yaml_text = make_yaml(draft["refresh_token"], login_customer_id)

  if settings.write_secret_manager:
    put_secret(settings.arba_project, settings.arba_google_ads_secret, yaml_text)

  ads_config = ""
  if settings.write_gcs:
    if not settings.arba_gcs_bucket:
      raise HTTPException(status_code=500, detail="ARBA_GCS_BUCKET is required when WRITE_GCS=true")
    ads_config = upload_to_gcs(settings.arba_gcs_bucket, settings.arba_gcs_object, yaml_text)

  update_requested = settings.update_cloud_run_job
  if update_requested:
    env_vars = {"ACCOUNT": ",".join(selected_ids)}
    if ads_config:
      env_vars["ADS_CONFIG"] = ads_config
    update_cloud_run_job_env(
      settings.arba_project,
      settings.arba_region,
      settings.arba_job_name,
      env_vars,
    )

  if update_requested and settings.run_arba_job_after_update:
    run_cloud_run_job(
      settings.arba_project,
      settings.arba_region,
      settings.arba_job_name,
    )

  delete_secret(settings.google_cloud_project, draft_id)

  status_message = (
    "The data update has started."
    if update_requested and settings.run_arba_job_after_update
    else "The setup has been saved."
  )
  body = f"""
    <h1>Setup complete</h1>
    <div class="card">
      <p><strong>{html.escape(selection_type)}:</strong> {html.escape(selection_label)}</p>
      <p>{html.escape(status_message)}</p>
    </div>
  """
  return render_page("Credentials saved", body)
