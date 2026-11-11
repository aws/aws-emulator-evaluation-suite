"""deployment-supersede-marks-previous-inactive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-supersede-marks-previous-inactive"
GROUP = "deployment-lifecycle"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a second deployment for a target that already has one supersedes the first:
    the prior deployment flips from ACTIVE/isLatestForTarget=True to INACTIVE/False, while
    the new one becomes the ACTIVE, isLatestForTarget=True deployment for that target."""
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    group_name = ctx.unique_name("sim2real-ggv2-tg-")
    group = iot.create_thing_group(
        thingGroupName=group_name, tags=[{"Key": "env", "Value": "sim2real-behavioral"}]
    )
    group_arn = group["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    dep1 = gg.create_deployment(
        targetArn=group_arn,
        deploymentName="sim2real-rev1",
        tags={"env": "sim2real-behavioral"},
    )
    dep1_id = dep1["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep1_id))

    got1 = gg.get_deployment(deploymentId=dep1_id)
    assert got1["deploymentStatus"] == "ACTIVE", (
        f"expected the first deployment to start ACTIVE, got {got1['deploymentStatus']!r}"
    )
    assert got1["isLatestForTarget"] is True, (
        f"expected the first deployment to be latest-for-target before any supersede, "
        f"got isLatestForTarget={got1['isLatestForTarget']!r}"
    )

    dep2 = gg.create_deployment(
        targetArn=group_arn,
        deploymentName="sim2real-rev2",
        tags={"env": "sim2real-behavioral"},
    )
    dep2_id = dep2["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(gg, dep2_id))
    assert dep2_id != dep1_id, (
        f"expected a distinct deployment id for the second CreateDeployment, "
        f"both were {dep1_id!r}"
    )

    final1 = _poll_until(
        lambda: gg.get_deployment(deploymentId=dep1_id),
        lambda d: d["deploymentStatus"] != "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert final1["deploymentStatus"] == "INACTIVE", (
        f"expected the superseded first deployment to settle INACTIVE, "
        f"got {final1['deploymentStatus']!r}"
    )
    assert final1["isLatestForTarget"] is False, (
        f"expected the superseded first deployment to lose latest-for-target, "
        f"got isLatestForTarget={final1['isLatestForTarget']!r}"
    )

    got2 = gg.get_deployment(deploymentId=dep2_id)
    assert got2["deploymentStatus"] == "ACTIVE", (
        f"expected the superseding second deployment to be ACTIVE, got {got2['deploymentStatus']!r}"
    )
    assert got2["isLatestForTarget"] is True, (
        f"expected the superseding second deployment to be latest-for-target, "
        f"got isLatestForTarget={got2['isLatestForTarget']!r}"
    )


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
