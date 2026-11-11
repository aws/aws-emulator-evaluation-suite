"""create-deployment-policies-reflected-in-get-deployment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-policies-reflected-in-get-deployment"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-default deploymentPolicies.failureHandlingPolicy given to CreateDeployment is reflected
    verbatim by GetDeployment, while a default deployment on the same target omits
    deploymentPolicies entirely rather than echoing back a ROLLBACK default."""
    iot = ctx.client("iot")
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-gg-policy-")
    thing = iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    default_dep = gg.create_deployment(targetArn=thing["thingArn"])
    default_id = default_dep["deploymentId"]
    ctx.on_cleanup(lambda: _safe_delete_deployment(ctx, default_id))
    default_fetched = gg.get_deployment(deploymentId=default_id)
    assert default_fetched.get("deploymentPolicies") is None, (
        f"expected no deploymentPolicies on a default deployment, got "
        f"{default_fetched.get('deploymentPolicies')!r}"
    )

    dep = gg.create_deployment(
        targetArn=thing["thingArn"],
        deploymentPolicies={"failureHandlingPolicy": "DO_NOTHING"},
    )
    deployment_id = dep["deploymentId"]
    ctx.on_cleanup(lambda: _safe_delete_deployment(ctx, deployment_id))

    fetched = gg.get_deployment(deploymentId=deployment_id)
    assert fetched["deploymentPolicies"]["failureHandlingPolicy"] == "DO_NOTHING", (
        f"expected DO_NOTHING, got {fetched['deploymentPolicies']!r}"
    )


# ===== helpers =====
def _safe_delete_deployment(ctx, deployment_id: str) -> None:
    gg = ctx.client("greengrassv2")
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
