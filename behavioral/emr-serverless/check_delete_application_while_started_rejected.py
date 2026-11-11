"""delete-application-while-started-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-application-while-started-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApplication on a STARTED application is rejected with ValidationException, the application
    is left running untouched, and deleting it succeeds once it has actually transitioned to STOPPED."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    emrs.start_application(applicationId=app_id)
    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STARTED",
        timeout_s=300.0,
        interval_s=5.0,
    )

    # AWS lists the allowed statuses in either order ("[CREATED, STOPPED]" or "[STOPPED, CREATED]"),
    # so the order is taken from the message and the rest is exact.
    code, message = _error(lambda: emrs.delete_application(applicationId=app_id))
    assert code == "ValidationException", f"expected ValidationException deleting a STARTED application, got {code!r}"
    statuses = "[STOPPED, CREATED]" if "[STOPPED, CREATED]" in (message or "") else "[CREATED, STOPPED]"
    assert message == (
        f"Application {app_id} must be in of the following statuses {statuses}. Current status: STARTED"
    ), message

    # effect absent: the application is still there and still STARTED.
    still_there = emrs.get_application(applicationId=app_id)["application"]
    assert still_there["state"] == "STARTED", f"expected rejected delete to leave application STARTED, got {still_there['state']!r}"

    # positive control: after it actually stops, deletion succeeds.
    emrs.stop_application(applicationId=app_id)
    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STOPPED",
        timeout_s=300.0,
        interval_s=5.0,
    )
    emrs.delete_application(applicationId=app_id)
    _poll_until(
        lambda: app_id in _list_ids(emrs),
        lambda present: present is False,
        timeout_s=120.0,
        interval_s=3.0,
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
