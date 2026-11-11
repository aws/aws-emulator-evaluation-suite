"""tag-resource-lifecycle-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-lifecycle-round-trip"
GROUP = "tagging"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes exactly
    the requested keys and leaves the rest intact."""
    bg = ctx.client("backup-gateway")
    arn = _create_hypervisor(ctx)

    bg.tag_resource(ResourceARN=arn, Tags=[
        {"Key": "sim2real-k1", "Value": "v1"},
        {"Key": "sim2real-k2", "Value": "v2"},
    ])

    tags = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-k1") == "v1", f"expected sim2real-k1=v1, got {tags.get('sim2real-k1')!r}"
    assert tags.get("sim2real-k2") == "v2", f"expected sim2real-k2=v2, got {tags.get('sim2real-k2')!r}"

    bg.untag_resource(ResourceARN=arn, TagKeys=["sim2real-k1"])

    tags_after = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert "sim2real-k1" not in tags_after, f"expected sim2real-k1 removed, tags now {tags_after!r}"
    assert tags_after.get("sim2real-k2") == "v2", (
        f"expected sim2real-k2 to survive untag of a different key, got {tags_after.get('sim2real-k2')!r}"
    )


def _create_hypervisor(ctx, host=None, name=None):
    bg = ctx.client("backup-gateway")
    kwargs = {
        "Name": name or ctx.unique_name("sim2real-bgw-"),
        "Host": host or f"{ctx.unique_name('sim2real-bgw-host-')}.example.com",
        "Username": "sim2real-user",
        "Password": "Sim2Real-Passw0rd!",
    }
    arn = bg.import_hypervisor_configuration(**kwargs)["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
