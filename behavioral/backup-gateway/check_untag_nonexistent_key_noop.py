"""untag-nonexistent-key-noop."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-nonexistent-key-noop"
GROUP = "tagging"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a tag key that was never set on the resource succeeds as a no-op
    and leaves the resource's existing tags untouched."""
    bg = ctx.client("backup-gateway")
    arn = _create_hypervisor(ctx)

    bg.tag_resource(ResourceARN=arn, Tags=[{"Key": "sim2real-kept", "Value": "kept-value"}])

    # This key was never set on the resource.
    bg.untag_resource(ResourceARN=arn, TagKeys=["sim2real-never-set"])

    tags = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-kept") == "kept-value", (
        f"expected sim2real-kept=kept-value to survive the no-op untag, got {tags!r}"
    )
    assert "sim2real-never-set" not in tags, (
        f"sim2real-never-set should never have existed, got {tags!r}"
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
