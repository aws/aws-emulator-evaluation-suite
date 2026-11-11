"""tag-resource-persists-on-connection."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-persists-on-connection"
GROUP = "tagging"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a connection is reflected by ListTagsForResource."""
    csc = ctx.client("codestar-connections")
    arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"), ProviderType="GitHub"
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=arn))

    csc.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behav"}],
    )

    tags = {t["Key"]: t["Value"] for t in csc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-env") == "test", f"expected sim2real-env=test, got {tags.get('sim2real-env')!r}"
    assert tags.get("sim2real-owner") == "behav", (
        f"expected sim2real-owner=behav, got {tags.get('sim2real-owner')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
