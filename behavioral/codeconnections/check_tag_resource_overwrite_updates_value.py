"""tag-resource-overwrite-updates-value."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-overwrite-updates-value"
GROUP = "data-plane"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-tagging an existing key overwrites its value rather than duplicating the entry."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    cc.tag_resource(ResourceArn=conn_arn, Tags=[{"Key": "Env", "Value": "dev"}])
    cc.tag_resource(ResourceArn=conn_arn, Tags=[{"Key": "Env", "Value": "prod"}])

    tags = cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]
    assert len(tags) == 1, f"expected exactly one tag after overwrite, got {tags!r}"
    assert tags[0] == {"Key": "Env", "Value": "prod"}, f"expected overwritten value 'prod', got {tags[0]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
