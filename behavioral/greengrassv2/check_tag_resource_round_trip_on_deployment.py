"""tag-resource-round-trip-on-deployment."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip-on-deployment"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a deployment ARN (not just
    a component version): tags are visible via both ListTagsForResource and GetDeployment's
    own tags field, and UntagResource actually clears them."""
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    thing_name = ctx.unique_name("sim2real-ggv2-thing-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    target_arn = f"arn:aws:iot:{ctx.region}:{account_id}:thing/{thing_name}"

    deployment_id = ggv2.create_deployment(targetArn=target_arn)["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))
    deployment_arn = f"arn:aws:greengrass:{ctx.region}:{account_id}:deployments:{deployment_id}"

    assert ggv2.list_tags_for_resource(resourceArn=deployment_arn).get("tags", {}) == {}

    ggv2.tag_resource(resourceArn=deployment_arn, tags={"sim2real-key": "sim2real-value"})

    tags = ggv2.list_tags_for_resource(resourceArn=deployment_arn)["tags"]
    assert tags.get("sim2real-key") == "sim2real-value", tags

    got = ggv2.get_deployment(deploymentId=deployment_id)
    assert got.get("tags", {}).get("sim2real-key") == "sim2real-value", got.get("tags")

    ggv2.untag_resource(resourceArn=deployment_arn, tagKeys=["sim2real-key"])
    tags_after = ggv2.list_tags_for_resource(resourceArn=deployment_arn).get("tags", {})
    assert "sim2real-key" not in tags_after, tags_after


def _cleanup_deployment(ggv2, deployment_id: str) -> None:
    _try(lambda: ggv2.cancel_deployment(deploymentId=deployment_id))
    _try(lambda: ggv2.delete_deployment(deploymentId=deployment_id))


def _try(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
