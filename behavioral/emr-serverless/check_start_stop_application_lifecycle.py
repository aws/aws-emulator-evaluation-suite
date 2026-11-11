"""start-stop-application-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-stop-application-lifecycle"
GROUP = "state"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartApplication and StopApplication drive CREATED -> STARTED -> STOPPED; after DeleteApplication
    GetApplication reports TERMINATED, the id leaves ListApplications, and a mutation fails with
    ValidationException and the exact message."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _delete_if_present(emrs, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    emrs.start_application(applicationId=app_id)
    started = _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)
    assert started == "STARTED"

    emrs.stop_application(applicationId=app_id)
    stopped = _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0)
    assert stopped == "STOPPED"

    emrs.delete_application(applicationId=app_id)
    terminated = _wait_for_application_state(ctx, app_id, {"TERMINATED"}, timeout_s=120.0)
    assert terminated == "TERMINATED"

    _wait_for_absent_from_list(emrs, app_id, timeout_s=120.0)

    # AWS lists the allowed statuses in either order ("[CREATED, STOPPED]" or "[STOPPED, CREATED]"),
    # so the order is taken from the message and the rest is exact.
    code, message = _error(lambda: emrs.start_application(applicationId=app_id))
    assert code == "ValidationException", (
        f"StartApplication on a deleted (TERMINATED) application must be rejected as invalid, got {code}"
    )
    statuses = "[STOPPED, CREATED]" if "[STOPPED, CREATED]" in (message or "") else "[CREATED, STOPPED]"
    assert message == (
        f"Application cannot be STARTED. Applications must be in one of the following statuses: {statuses}"
    ), message


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_absent_from_list(emrs, app_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_ids: list[str] = []
    while time.monotonic() < deadline:
        last_ids = _list_ids(emrs)
        if app_id not in last_ids:
            return
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} still present in ListApplications: {last_ids}")


def _list_ids(emrs):
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        page = emrs.list_applications(**kwargs)
        ids.extend(a["id"] for a in page["applications"])
        token = page.get("nextToken")
        if not token:
            break
    return ids


def _delete_if_present(emrs, app_id):
    from botocore.exceptions import ClientError

    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ValidationException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
