"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "data-plane"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named key(s), leaving the rest intact."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    cc.tag_resource(
        ResourceArn=conn_arn,
        Tags=[{"Key": "Environment", "Value": "test"}, {"Key": "Owner", "Value": "sim2real"}],
    )
    cc.untag_resource(ResourceArn=conn_arn, TagKeys=["Owner"])

    tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]}
    assert tags == {"Environment": "test"}, "expected only Environment to remain, actual_tags=" + repr(tags)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
