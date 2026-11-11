"""untag-resource-nonexistent-key-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-key-is-noop"
GROUP = "state"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a key that was never applied to the resource succeeds as a no-op,
    leaving the resource's existing tags untouched.
    """
    cc = ctx.client("codestar-connections")
    arn = cc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-cn-")[:32],
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-present", "Value": "yes"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: _safe_delete_connection(cc, arn))

    # this key was never applied to the resource
    cc.untag_resource(ResourceArn=arn, TagKeys=["sim2real-never-applied"])

    tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-present") == "yes", f"expected pre-existing tag preserved, got {tags}"
    assert "sim2real-never-applied" not in tags, (
        f"UntagResource on an absent key must not create it, got {tags}"
    )
    assert len(tags) == 1, f"expected exactly the one pre-existing tag, got {tags}"


def _safe_delete_connection(cc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cc.delete_connection(ConnectionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
