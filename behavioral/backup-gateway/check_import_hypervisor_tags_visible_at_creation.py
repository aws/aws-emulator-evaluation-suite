"""import-hypervisor-tags-visible-at-creation."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-hypervisor-tags-visible-at-creation"
GROUP = "tagging"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed directly to ImportHypervisorConfiguration are attached at creation time
    and are visible through ListTagsForResource without a separate TagResource call."""
    bg = ctx.client("backup-gateway")
    name = ctx.unique_name("sim2real-bgw-")
    host = f"{ctx.unique_name('sim2real-bgw-host-')}.example.com"
    arn = bg.import_hypervisor_configuration(
        Name=name,
        Host=host,
        Username="sim2real-user",
        Password="Sim2Real-Passw0rd!",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    tags = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-owner") == "behavioral-suite", (
        f"expected sim2real-owner=behavioral-suite visible via ListTagsForResource "
        f"without a separate TagResource call, got tags={tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
