"""cancel-deployment-already-canceled-idempotent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-deployment-already-canceled-idempotent"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelDeployment on an already-CANCELED deployment succeeds and leaves it CANCELED, while
    canceling a separate, still-ACTIVE deployment still transitions it to CANCELED."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_a_name = ctx.unique_name("sim2real-ggv2-tga-")
    group_a_arn = iot.create_thing_group(
        thingGroupName=group_a_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_a_name))

    group_b_name = ctx.unique_name("sim2real-ggv2-tgb-")
    group_b_arn = iot.create_thing_group(
        thingGroupName=group_b_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_b_name))

    dep_a_id = gg.create_deployment(
        targetArn=group_a_arn, tags={"sim2real-check": CHECK}
    )["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep_a_id))
    dep_b_id = gg.create_deployment(
        targetArn=group_b_arn, tags={"sim2real-check": CHECK}
    )["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep_b_id))

    gg.cancel_deployment(deploymentId=dep_a_id)
    _poll_until(
        lambda: gg.get_deployment(deploymentId=dep_a_id)["deploymentStatus"],
        lambda status: status == "CANCELED",
        timeout_s=60,
        interval_s=3,
    )

    # Idempotent re-cancel of an already-CANCELED deployment must succeed without error and
    # must not change the terminal status.
    gg.cancel_deployment(deploymentId=dep_a_id)
    status_a = gg.get_deployment(deploymentId=dep_a_id)["deploymentStatus"]
    assert status_a == "CANCELED", f"expected re-cancel to leave status CANCELED, got {status_a!r}"

    status_b = gg.get_deployment(deploymentId=dep_b_id)["deploymentStatus"]
    assert status_b == "ACTIVE", f"expected deployment B still ACTIVE before its own cancel, got {status_b!r}"
    gg.cancel_deployment(deploymentId=dep_b_id)
    final_b = _poll_until(
        lambda: gg.get_deployment(deploymentId=dep_b_id)["deploymentStatus"],
        lambda status: status != "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert final_b == "CANCELED", f"expected deployment B to transition to CANCELED, got {final_b!r}"



def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


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
