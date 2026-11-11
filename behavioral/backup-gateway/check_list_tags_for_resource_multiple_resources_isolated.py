"""list-tags-for-resource-multiple-resources-isolated."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-tags-for-resource-multiple-resources-isolated"
GROUP = "tagging"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags are scoped per resource: tagging one Hypervisor does not leak into the tag set of
    a different Hypervisor."""
    bg = ctx.client("backup-gateway")
    arn_one = _create_hypervisor(ctx)
    arn_two = _create_hypervisor(ctx)

    bg.tag_resource(ResourceARN=arn_one, Tags=[{"Key": "sim2real-scope", "Value": "one"}])
    bg.tag_resource(ResourceARN=arn_two, Tags=[{"Key": "sim2real-scope", "Value": "two"}])

    tags_one = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn_one)["Tags"]}
    tags_two = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn_two)["Tags"]}

    assert tags_one.get("sim2real-scope") == "one", (
        f"expected hypervisor one's sim2real-scope tag to read back as 'one', got {tags_one!r}"
    )
    assert tags_two.get("sim2real-scope") == "two", (
        f"expected hypervisor two's sim2real-scope tag to read back as 'two', got {tags_two!r}"
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
