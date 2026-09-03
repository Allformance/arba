import unittest
from unittest import mock

from fastapi import HTTPException

from onboarding import app


class FakeResponse:
  def __init__(self, payload: dict, status_code: int = 200):
    self.payload = payload
    self.status_code = status_code
    self.text = ""

  def json(self) -> dict:
    return self.payload


class FakeSession:
  def __init__(self, job: dict):
    self.job = job
    self.get_calls: list[str] = []
    self.patch_calls: list[tuple[str, dict]] = []

  def get(self, url: str) -> FakeResponse:
    self.get_calls.append(url)
    if "/operations/" in url:
      return FakeResponse({"name": "projects/test/locations/test/operations/1", "done": True})
    return FakeResponse(self.job)

  def patch(self, url: str, json: dict) -> FakeResponse:
    self.patch_calls.append((url, json))
    return FakeResponse({"name": "projects/test/locations/test/operations/1"})


class CloudRunJobUpdateTest(unittest.TestCase):
  def test_updates_full_job_without_update_mask_and_waits(self) -> None:
    job = {
      "name": "projects/test/locations/test/jobs/arba",
      "etag": "etag",
      "template": {
        "taskCount": 1,
        "template": {
          "maxRetries": 1,
          "containers": [
            {
              "image": "example.test/arba",
              "env": [
                {"name": "ACCOUNT", "value": "0"},
                {"name": "UNCHANGED", "value": "value"},
              ],
            }
          ],
        },
      },
    }
    session = FakeSession(job)

    with (
      mock.patch.object(app, "authorized_session", return_value=session),
      mock.patch.object(app.time, "sleep"),
    ):
      app.update_cloud_run_job_env(
        "test",
        "test",
        "arba",
        {"ACCOUNT": "123", "ADS_CONFIG": "gs://test/arba/google-ads.yaml"},
      )

    patch_url, patch_body = session.patch_calls[0]
    self.assertEqual(
      patch_url,
      "https://run.googleapis.com/v2/projects/test/locations/test/jobs/arba",
    )
    self.assertNotIn("updateMask", patch_url)
    self.assertEqual(patch_body["template"]["taskCount"], 1)
    self.assertEqual(
      {item["name"]: item["value"] for item in patch_body["template"]["template"]["containers"][0]["env"]},
      {
        "ACCOUNT": "123",
        "ADS_CONFIG": "gs://test/arba/google-ads.yaml",
        "UNCHANGED": "value",
      },
    )
    self.assertTrue(any("/operations/" in url for url in session.get_calls))


class TargetSelectionTest(unittest.TestCase):
  def setUp(self) -> None:
    self.accounts = [
      {
        "id": "100",
        "name": "Main MCC",
        "manager": True,
        "login_customer_id": "100",
      },
      {
        "id": "101",
        "name": "Account One",
        "manager": False,
        "login_customer_id": "100",
      },
      {
        "id": "201",
        "name": "Account Two",
        "manager": False,
        "login_customer_id": "200",
      },
    ]

  def test_manager_is_the_only_target(self) -> None:
    selected, login_customer_id, _, _ = app.resolve_target(
      self.accounts, "manager", "100", ["101"]
    )
    self.assertEqual(selected, ["100"])
    self.assertEqual(login_customer_id, "100")

  def test_accounts_from_different_mccs_are_rejected(self) -> None:
    with self.assertRaises(HTTPException):
      app.resolve_target(self.accounts, "accounts", "", ["101", "201"])


if __name__ == "__main__":
  unittest.main()
