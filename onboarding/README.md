# ARBA OAuth Onboarding

This is a small Cloud Run service that lets a client connect Google Ads access
through OAuth and then writes the `google-ads.yaml` used by ARBA.

The service does not change ARBA query/runtime code. It is an onboarding layer
around an existing Cloud Run job.

## Flow

1. A user opens `/connect`.
2. Google OAuth returns to `/oauth/callback`.
3. The service exchanges the code for a refresh token.
4. The service lists Google Ads accounts available to the user.
5. The user chooses either an MCC or one or more individual accounts.
6. The service writes `google-ads.yaml` to Secret Manager and, if configured,
   to GCS for ARBA compatibility.
7. The service automatically updates the ARBA Cloud Run job env vars:
   `ACCOUNT` and `ADS_CONFIG`, and can start the job immediately.

## Required Environment Variables

```text
APP_BASE_URL=https://<onboarding-service-url>
OAUTH_CLIENT_ID=<oauth-client-id>
OAUTH_CLIENT_SECRET=<oauth-client-secret>
GOOGLE_ADS_DEVELOPER_TOKEN=<google-ads-developer-token>
STATE_SIGNING_SECRET=<random-long-secret>
GOOGLE_CLOUD_PROJECT=<gcp-project>
```

## ARBA Target Configuration

```text
ARBA_PROJECT=<gcp-project>              # defaults to GOOGLE_CLOUD_PROJECT
ARBA_REGION=us-central1                 # default
ARBA_JOB_NAME=arba                      # default
ARBA_GCS_BUCKET=<bucket-name>           # defaults to ARBA_PROJECT
ARBA_GCS_OBJECT=arba/google-ads.yaml    # default
ARBA_GOOGLE_ADS_SECRET=arba-google-ads-yaml
UPDATE_CLOUD_RUN_JOB=true               # default
RUN_ARBA_JOB_AFTER_UPDATE=false         # default
WRITE_SECRET_MANAGER=true               # default
WRITE_GCS=true                          # default when ARBA_GCS_BUCKET exists
GOOGLE_ADS_API_VERSION=v23              # default
```

## OAuth Setup

Create an OAuth client for a Web application and add this redirect URI:

```text
https://<onboarding-service-url>/oauth/callback
```

The app requests:

```text
https://www.googleapis.com/auth/adwords
```

For external clients, the OAuth app may need Google verification before this
can be used smoothly outside the test-user allowlist.

## IAM For The Onboarding Service Account

The Cloud Run service account needs permission to:

- create and access Secret Manager secrets;
- write the configured GCS object;
- update the target ARBA Cloud Run job.

Practical roles for the first deployment:

```text
roles/secretmanager.admin
roles/storage.objectAdmin
roles/run.admin
```

These can be narrowed later after the first production rollout.

## Deploy

```bash
PROJECT_ID=<project> \
OAUTH_CLIENT_ID=<oauth-client-id> \
./onboarding/deploy.sh
```

The script prompts for missing sensitive values and stores them in Secret
Manager, then prints the OAuth redirect URI that must be added to the OAuth
client.
