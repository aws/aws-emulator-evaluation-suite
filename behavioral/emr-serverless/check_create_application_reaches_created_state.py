"""create-application-reaches-created-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-application-reaches-created-state"
GROUP = "application-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication provisions an application that reaches the CREATED state with the requested config persisted."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    token = ctx.unique_name("sim2real-emrs-tok-")

    resp = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=token,
    )
    app_id = resp["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    assert resp["arn"].endswith(f"/applications/{app_id}"), (
        f"expected arn ending in /applications/{app_id}, got {resp['arn']!r}"
    )
    assert "arn:aws" in resp["arn"] and ":emr-serverless:" in resp["arn"], (
        f"expected an emr-serverless arn, got {resp['arn']!r}"
    )

    app = _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"],
        lambda a: a["state"] != "CREATING",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert app["state"] == "CREATED", f"expected state CREATED, got {app['state']!r}"
    assert app["name"] == name, f"expected name {name!r}, got {app['name']!r}"
    assert app["releaseLabel"] == "emr-7.9.0", (
        f"expected releaseLabel 'emr-7.9.0', got {app['releaseLabel']!r}"
    )
    assert app["type"].upper() == "SPARK", f"expected type SPARK, got {app['type']!r}"


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
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if state in ("STARTED", "STARTING"):
        try:
            emrs.stop_application(applicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                state = emrs.get_application(applicationId=app_id)["application"]["state"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            if state == "STOPPED":
                break
            time.sleep(5)
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
