"""delete-deployment-active-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-deployment-active-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeployment on a still-ACTIVE deployment is rejected with ValidationException and leaves
    it in place; after a cancel it succeeds, GetDeployment confirms it is gone, and a further
    CancelDeployment on the deleted id is rejected too."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    group_arn = iot.create_thing_group(
        thingGroupName=group_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    dep_id = gg.create_deployment(
        targetArn=group_arn,
        tags={"sim2real-check": CHECK},
    )["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep_id))

    status = gg.get_deployment(deploymentId=dep_id)["deploymentStatus"]
    assert status == "ACTIVE", f"expected freshly created deployment ACTIVE, got {status!r}"

    code, message = _client_error(lambda: gg.delete_deployment(deploymentId=dep_id))
    assert code == "ValidationException", f"got code={code!r}"
    expected = "Invalid Input: Greengrass deployment must be canceled before deletion"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    status = gg.get_deployment(deploymentId=dep_id)["deploymentStatus"]
    assert status == "ACTIVE", f"rejected delete must not change status, got {status!r}"

    gg.cancel_deployment(deploymentId=dep_id)
    _poll_until(
        lambda: gg.get_deployment(deploymentId=dep_id)["deploymentStatus"],
        lambda status: status != "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )

    gg.delete_deployment(deploymentId=dep_id)
    final_code, final_message = _poll_until_rejected(
        lambda: gg.get_deployment(deploymentId=dep_id), timeout_s=30, interval_s=2
    )
    assert final_code == "ResourceNotFoundException", f"got code={final_code!r}"
    assert final_message == "Deployment not found", f"got message={final_message!r}"

    mutate_code, mutate_message = _client_error(lambda: gg.cancel_deployment(deploymentId=dep_id))
    assert mutate_code == "ResourceNotFoundException", (
        f"a mutation on the deleted deployment id must also be rejected, got code={mutate_code!r}"
    )
    assert mutate_message == "Deployment not found", f"got message={mutate_message!r}"


def _poll_until_rejected(fn, timeout_s=60.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message); a call that keeps
    succeeding past the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"call still succeeded after {timeout_s}s, last result={result!r}")
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _cleanup_deployment(gg, deployment_id: str) -> None:
    deadline = time.monotonic() + 15.0
    try:
        gg.cancel_deployment(deploymentId=deployment_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        # A deployment that is not ACTIVE cannot be canceled; DeleteDeployment decides.
        if code not in ("ConflictException", "ValidationException"):
            raise
    while True:
        try:
            gg.delete_deployment(deploymentId=deployment_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # DeleteDeployment refuses ("must be canceled before deletion") until the cancel
            # has taken effect; retry only that refusal.
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
