"""list-applications-filters-by-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-applications-filters-by-state"
GROUP = "application-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplications with a states filter includes an application matching that state and excludes it otherwise."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    token = ctx.unique_name("sim2real-emrs-tok-")

    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=token,
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "CREATED",
        timeout_s=60.0,
        interval_s=3.0,
    )

    created_ids = _list_ids(emrs, states=["CREATED"])
    assert app_id in created_ids, (
        f"expected {app_id} in ListApplications(states=['CREATED']) result {created_ids}"
    )

    started_ids = _list_ids(emrs, states=["STARTED"])
    assert app_id not in started_ids, (
        f"expected {app_id} absent from ListApplications(states=['STARTED']) result {started_ids} "
        "(application was never started)"
    )


def _list_ids(emrs, states):
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"maxResults": 50, "states": states}
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


def _cleanup_application(emrs, app_id):
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
