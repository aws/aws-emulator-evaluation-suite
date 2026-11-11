"""untag-resource-removes-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tags"
GROUP = "tagging"
SERVICES = ["codestar-connections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested key, leaving the others intact."""
    csc = ctx.client("codestar-connections")
    arn = csc.create_connection(
        ConnectionName=ctx.unique_name("sim2real-behav-conn-"),
        ProviderType="GitHub",
        Tags=[{"Key": "sim2real-keep", "Value": "yes"}, {"Key": "sim2real-drop", "Value": "yes"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: csc.delete_connection(ConnectionArn=arn))

    before = {t["Key"]: t["Value"] for t in csc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert before.get("sim2real-keep") == "yes", f"expected sim2real-keep=yes before untag, got {before!r}"
    assert before.get("sim2real-drop") == "yes", f"expected sim2real-drop=yes before untag, got {before!r}"

    csc.untag_resource(ResourceArn=arn, TagKeys=["sim2real-drop"])

    after = {t["Key"]: t["Value"] for t in csc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert after.get("sim2real-keep") == "yes", f"expected sim2real-keep=yes to survive untag, got {after!r}"
    assert "sim2real-drop" not in after, f"expected sim2real-drop removed by untag, still present in {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
