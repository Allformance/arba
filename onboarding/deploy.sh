#!/usr/bin/env bash

set -euo pipefail

SERVICE_NAME=${SERVICE_NAME:-arba-onboarding}
LOCATION=${LOCATION:-us-central1}
PROJECT_ID=${PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-}}
ARBA_PROJECT=${ARBA_PROJECT:-$PROJECT_ID}
ARBA_REGION=${ARBA_REGION:-us-central1}
ARBA_JOB_NAME=${ARBA_JOB_NAME:-arba}
ARBA_GCS_BUCKET=${ARBA_GCS_BUCKET:-$ARBA_PROJECT}
ARBA_GCS_OBJECT=${ARBA_GCS_OBJECT:-arba/google-ads.yaml}
ARBA_GOOGLE_ADS_SECRET=${ARBA_GOOGLE_ADS_SECRET:-arba-google-ads-yaml}
GOOGLE_ADS_API_VERSION=${GOOGLE_ADS_API_VERSION:-v23}
WRITE_SECRET_MANAGER=${WRITE_SECRET_MANAGER:-true}
WRITE_GCS=${WRITE_GCS:-true}
UPDATE_CLOUD_RUN_JOB=${UPDATE_CLOUD_RUN_JOB:-true}
RUN_ARBA_JOB_AFTER_UPDATE=${RUN_ARBA_JOB_AFTER_UPDATE:-false}
APP_BASE_URL=${APP_BASE_URL:-}

OAUTH_CLIENT_SECRET_SECRET=${OAUTH_CLIENT_SECRET_SECRET:-arba-onboarding-oauth-client-secret}
GOOGLE_ADS_DEVELOPER_TOKEN_SECRET=${GOOGLE_ADS_DEVELOPER_TOKEN_SECRET:-arba-onboarding-google-ads-developer-token}
STATE_SIGNING_SECRET_SECRET=${STATE_SIGNING_SECRET_SECRET:-arba-onboarding-state-signing-secret}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

prompt_if_empty() {
  local var_name="$1"
  local prompt="$2"
  local value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    read -r -p "$prompt: " value
    printf -v "$var_name" '%s' "$value"
  fi
}

prompt_secret_if_empty() {
  local var_name="$1"
  local prompt="$2"
  local value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    read -r -s -p "$prompt: " value
    echo
    printf -v "$var_name" '%s' "$value"
  fi
}

ensure_secret() {
  local project="$1"
  local secret_id="$2"
  if ! gcloud secrets describe "$secret_id" --project "$project" >/dev/null 2>&1; then
    gcloud secrets create "$secret_id" --project "$project" --replication-policy=automatic >/dev/null
  fi
}

put_secret_value() {
  local project="$1"
  local secret_id="$2"
  local value="$3"
  ensure_secret "$project" "$secret_id"
  printf '%s' "$value" | gcloud secrets versions add "$secret_id" --project "$project" --data-file=- >/dev/null
}

secret_exists() {
  local project="$1"
  local secret_id="$2"
  gcloud secrets describe "$secret_id" --project "$project" >/dev/null 2>&1
}

generate_state_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  fi
}

enable_apis() {
  local project="$1"
  gcloud services enable \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    secretmanager.googleapis.com \
    storage.googleapis.com \
    googleads.googleapis.com \
    generativelanguage.googleapis.com \
    --project "$project"
}

grant_runtime_roles() {
  local project="$1"
  local service_account="$2"
  for role in roles/secretmanager.admin roles/storage.objectAdmin roles/run.admin; do
    gcloud projects add-iam-policy-binding "$project" \
      --member "serviceAccount:$service_account" \
      --role "$role" \
      --condition=None \
      --quiet >/dev/null
  done
}

prompt_if_empty PROJECT_ID "Google Cloud project for onboarding"
ARBA_PROJECT=${ARBA_PROJECT:-$PROJECT_ID}
ARBA_GCS_BUCKET=${ARBA_GCS_BUCKET:-$ARBA_PROJECT}

enable_apis "$PROJECT_ID"
if [[ "$ARBA_PROJECT" != "$PROJECT_ID" ]]; then
  enable_apis "$ARBA_PROJECT"
fi

prompt_if_empty OAUTH_CLIENT_ID "OAuth client ID"
if ! secret_exists "$PROJECT_ID" "$OAUTH_CLIENT_SECRET_SECRET"; then
  prompt_secret_if_empty OAUTH_CLIENT_SECRET "OAuth client secret"
  put_secret_value "$PROJECT_ID" "$OAUTH_CLIENT_SECRET_SECRET" "$OAUTH_CLIENT_SECRET"
elif [[ -n "${OAUTH_CLIENT_SECRET:-}" ]]; then
  put_secret_value "$PROJECT_ID" "$OAUTH_CLIENT_SECRET_SECRET" "$OAUTH_CLIENT_SECRET"
fi

if ! secret_exists "$PROJECT_ID" "$GOOGLE_ADS_DEVELOPER_TOKEN_SECRET"; then
  prompt_secret_if_empty GOOGLE_ADS_DEVELOPER_TOKEN "Google Ads developer token"
  put_secret_value "$PROJECT_ID" "$GOOGLE_ADS_DEVELOPER_TOKEN_SECRET" "$GOOGLE_ADS_DEVELOPER_TOKEN"
elif [[ -n "${GOOGLE_ADS_DEVELOPER_TOKEN:-}" ]]; then
  put_secret_value "$PROJECT_ID" "$GOOGLE_ADS_DEVELOPER_TOKEN_SECRET" "$GOOGLE_ADS_DEVELOPER_TOKEN"
fi

if ! secret_exists "$PROJECT_ID" "$STATE_SIGNING_SECRET_SECRET"; then
  STATE_SIGNING_SECRET=${STATE_SIGNING_SECRET:-$(generate_state_secret)}
  put_secret_value "$PROJECT_ID" "$STATE_SIGNING_SECRET_SECRET" "$STATE_SIGNING_SECRET"
elif [[ -n "${STATE_SIGNING_SECRET:-}" ]]; then
  put_secret_value "$PROJECT_ID" "$STATE_SIGNING_SECRET_SECRET" "$STATE_SIGNING_SECRET"
fi

project_number="$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")"
SERVICE_ACCOUNT=${SERVICE_ACCOUNT:-${project_number}-compute@developer.gserviceaccount.com}

if [[ "$WRITE_GCS" == "true" ]]; then
  if ! gcloud storage ls "gs://$ARBA_GCS_BUCKET" --project "$ARBA_PROJECT" >/dev/null 2>&1; then
    gcloud storage buckets create "gs://$ARBA_GCS_BUCKET" \
      --project "$ARBA_PROJECT" \
      --location "$ARBA_REGION" \
      --uniform-bucket-level-access
  fi
fi

grant_runtime_roles "$PROJECT_ID" "$SERVICE_ACCOUNT"
if [[ "$ARBA_PROJECT" != "$PROJECT_ID" ]]; then
  grant_runtime_roles "$ARBA_PROJECT" "$SERVICE_ACCOUNT"
fi

initial_base_url=${APP_BASE_URL:-https://placeholder.invalid}

gcloud run deploy "$SERVICE_NAME" \
  --source "$script_dir" \
  --project "$PROJECT_ID" \
  --region "$LOCATION" \
  --allow-unauthenticated \
  --service-account "$SERVICE_ACCOUNT" \
  --set-env-vars "APP_BASE_URL=$initial_base_url,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID,ARBA_PROJECT=$ARBA_PROJECT,ARBA_REGION=$ARBA_REGION,ARBA_JOB_NAME=$ARBA_JOB_NAME,ARBA_GCS_BUCKET=$ARBA_GCS_BUCKET,ARBA_GCS_OBJECT=$ARBA_GCS_OBJECT,ARBA_GOOGLE_ADS_SECRET=$ARBA_GOOGLE_ADS_SECRET,WRITE_SECRET_MANAGER=$WRITE_SECRET_MANAGER,WRITE_GCS=$WRITE_GCS,UPDATE_CLOUD_RUN_JOB=$UPDATE_CLOUD_RUN_JOB,RUN_ARBA_JOB_AFTER_UPDATE=$RUN_ARBA_JOB_AFTER_UPDATE,GOOGLE_ADS_API_VERSION=$GOOGLE_ADS_API_VERSION" \
  --set-secrets "OAUTH_CLIENT_SECRET=$OAUTH_CLIENT_SECRET_SECRET:latest,GOOGLE_ADS_DEVELOPER_TOKEN=$GOOGLE_ADS_DEVELOPER_TOKEN_SECRET:latest,STATE_SIGNING_SECRET=$STATE_SIGNING_SECRET_SECRET:latest"

service_url="$(gcloud run services describe "$SERVICE_NAME" --project "$PROJECT_ID" --region "$LOCATION" --format="value(status.url)")"
APP_BASE_URL=${APP_BASE_URL:-$service_url}

gcloud run services update "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$LOCATION" \
  --update-env-vars "APP_BASE_URL=$APP_BASE_URL"

echo "Onboarding service: $APP_BASE_URL"
echo "OAuth redirect URI: $APP_BASE_URL/oauth/callback"
