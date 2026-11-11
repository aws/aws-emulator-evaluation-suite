"""tags-removed-with-hypervisor-deletion."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tags-removed-with-hypervisor-deletion"
GROUP = "lifecycle"
SERVICES = ["backup-gateway"]

HYPERVISOR_NOT_FOUND = "The hypervisor is not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a Hypervisor is deleted, its tag store goes with it: ListTagsForResource on the
    now-deleted ARN returns ResourceNotFoundException rather than stale tag data."""
    bg = ctx.client("backup-gateway")
    arn = _create_hypervisor(ctx)
    bg.tag_resource(ResourceARN=arn, Tags=[{"Key": "sim2real-ephemeral", "Value": "x"}])

    tags = {t["Key"]: t["Value"] for t in bg.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags.get("sim2real-ephemeral") == "x", f"expected tag not visible before delete: {tags!r}"

    bg.delete_hypervisor(HypervisorArn=arn)

    got = _client_error(lambda: bg.list_tags_for_resource(ResourceArn=arn))
    assert got == ("ResourceNotFoundException", HYPERVISOR_NOT_FOUND), (
        f"expected ResourceNotFoundException {HYPERVISOR_NOT_FOUND!r}, got {got!r}"
    )

    mutation = _client_error(
        lambda: bg.tag_resource(ResourceARN=arn, Tags=[{"Key": "sim2real-post-delete", "Value": "y"}])
    )
    assert mutation == ("ResourceNotFoundException", HYPERVISOR_NOT_FOUND), (
        f"TagResource on a deleted HypervisorArn must also fail not-found, got {mutation!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
