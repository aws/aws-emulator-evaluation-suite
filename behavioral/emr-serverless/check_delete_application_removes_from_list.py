"""delete-application-removes-from-list."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-application-removes-from-list"
GROUP = "application-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CREATED application is visible in ListApplications and disappears once DeleteApplication completes."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    token = ctx.unique_name("sim2real-emrs-tok-")

    app_id = emrs.create_application(
        name=name, releaseLabel="emr-7.9.0", type="SPARK", clientToken=token
    )["applicationId"]
    ctx.on_cleanup(lambda: _safe_delete(emrs, app_id))

    _poll_until(
        lambda: _list_ids(emrs),
        lambda ids: app_id in ids,
        timeout_s=60.0,
        interval_s=3.0,
    )

    emrs.delete_application(applicationId=app_id)

    _poll_until(
        lambda: _list_ids(emrs),
        lambda ids: app_id not in ids,
        timeout_s=120.0,
        interval_s=3.0,
    )

    # unusable: emr-serverless soft-deletes (GetApplication keeps answering with
    # state TERMINATED rather than 404ing), so "gone" is proven by list-absence
    # above and "unusable" is proven by a mutation on the dead id failing.
    state = emrs.get_application(applicationId=app_id)["application"]["state"]
    assert state == "TERMINATED", f"expected TERMINATED after delete, got {state!r}"

    # AWS lists the allowed statuses in either order ("[CREATED, STOPPED]" or "[STOPPED, CREATED]"),
    # so the order is taken from the message and the rest is exact.
    code, message = _error(lambda: emrs.start_application(applicationId=app_id))
    assert code == "ValidationException", f"expected ValidationException starting a TERMINATED application, got {code!r}"
    statuses = "[STOPPED, CREATED]" if "[STOPPED, CREATED]" in (message or "") else "[CREATED, STOPPED]"
    assert message == (
        f"Application cannot be STARTED. Applications must be in one of the following statuses: {statuses}"
    ), message


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


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
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
