"""tag-resource-round-trip-on-deployment-v2."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip-on-deployment-v2"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource work on a deployment ARN, not just a component
    ARN -- the tagging surface is generic across greengrassv2 resource types."""
    iot = ctx.client("iot")
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-gg-deptag-")
    thing = iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    dep = gg.create_deployment(targetArn=thing["thingArn"])
    deployment_id = dep["deploymentId"]
    ctx.on_cleanup(lambda: _safe_delete_deployment(ctx, deployment_id))

    gg.get_deployment(deploymentId=deployment_id)
    # Deployment resources are addressed for tagging purposes by an ARN of the form
    # arn:aws:greengrass:<region>:<account>:deployments:<deploymentId>
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    deployment_arn = f"arn:aws:greengrass:{ctx.region}:{account}:deployments:{deployment_id}"

    gg.tag_resource(resourceArn=deployment_arn, tags={"purpose": "sim2real-behavioral"})
    tags_after_tag = gg.list_tags_for_resource(resourceArn=deployment_arn)["tags"]
    assert tags_after_tag.get("purpose") == "sim2real-behavioral", (
        f"expected tag purpose=sim2real-behavioral on {deployment_arn} after TagResource, "
        f"got {tags_after_tag!r}"
    )

    gg.untag_resource(resourceArn=deployment_arn, tagKeys=["purpose"])
    tags_after_untag = gg.list_tags_for_resource(resourceArn=deployment_arn)["tags"]
    assert "purpose" not in tags_after_untag, (
        f"expected tag 'purpose' removed from {deployment_arn} after UntagResource, "
        f"got {tags_after_untag!r}"
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
