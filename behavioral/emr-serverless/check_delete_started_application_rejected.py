"""delete-started-application-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-started-application-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApplication on a STARTED application is rejected; it must be stopped first."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.0.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        tags={"sim2real": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: _safe_delete(emrs, app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    emrs.start_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)

    # AWS lists the allowed statuses in either order ("[CREATED, STOPPED]" or "[STOPPED, CREATED]"),
    # so the order is taken from the message and the rest is exact.
    code, message = _error(lambda: emrs.delete_application(applicationId=app_id))
    assert code == "ValidationException", (
        f"DeleteApplication on a STARTED application returned {code!r}, expected "
        "'ValidationException'"
    )
    statuses = "[STOPPED, CREATED]" if "[STOPPED, CREATED]" in (message or "") else "[CREATED, STOPPED]"
    assert message == (
        f"Application {app_id} must be in of the following statuses {statuses}. Current status: STARTED"
    ), message

    # effect absent: the application must still exist, still STARTED
    app = emrs.get_application(applicationId=app_id)["application"]
    assert app["state"] == "STARTED", (
        f"the rejected delete left the application in state {app['state']!r}, expected it to "
        "remain 'STARTED'"
    )

    # positive control: stop it, then delete succeeds
    emrs.stop_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0)
    emrs.delete_application(applicationId=app_id)
    final_state = _wait_for_application_state(ctx, app_id, {"TERMINATED"}, timeout_s=180.0)
    assert final_state == "TERMINATED", (
        f"deleting a STOPPED application ended in state {final_state!r}, expected 'TERMINATED'"
    )


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


def _safe_delete(emrs, app_id):
    from botocore.exceptions import ClientError
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
