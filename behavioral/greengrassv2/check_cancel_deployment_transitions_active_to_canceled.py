"""cancel-deployment-transitions-active-to-canceled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-deployment-transitions-active-to-canceled"
GROUP = "deployment-lifecycle"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelDeployment moves an ACTIVE deployment to CANCELED, observable via GetDeployment."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    group = iot.create_thing_group(
        thingGroupName=group_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    group_arn = group["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    dep = gg.create_deployment(targetArn=group_arn, tags={"sim2real-check": CHECK})
    deployment_id = dep["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, deployment_id))

    initial = gg.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
    assert initial == "ACTIVE", f"expected freshly created deployment ACTIVE, got {initial!r}"

    gg.cancel_deployment(deploymentId=deployment_id)

    final = _poll_until(
        lambda: gg.get_deployment(deploymentId=deployment_id)["deploymentStatus"],
        lambda status: status != "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert final == "CANCELED", f"expected CANCELED after cancel_deployment, got {final!r}"


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
