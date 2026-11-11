"""start-metadata-sync-state-transition."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "start-metadata-sync-state-transition"
GROUP = "state"
SERVICES = ["backup-gateway"]

MAPPINGS_NOT_CONFIGURED = "HypervisorPropertyMappings is not configured for the Hypervisor"
HYPERVISOR_ARN_PATTERN = r"arn:(aws|aws-cn|aws-us-gov):backup-gateway(:[a-zA-Z-0-9]+){3}\/[a-zA-Z-0-9]+"


def _arn_pattern_message(value: str) -> str:
    return (
        f"1 validation error detected: Value '{value}' at 'hypervisorArn' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {HYPERVISOR_ARN_PATTERN}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartVirtualMachinesMetadataSync on a hypervisor without property mappings, or a nonexistent
    one, fails with AccessDeniedException and starts no sync; a malformed ARN gets
    ValidationException."""
    bg = ctx.client("backup-gateway")
    arn = _create_hypervisor(ctx)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    ghost_arn = (
        f"arn:aws:backup-gateway:{ctx.region}:{account_id}:hypervisor/"
        f"{ctx.unique_name('sim2real-bgw-ghost-')}"
    )
    ghost = _client_error(lambda: bg.start_virtual_machines_metadata_sync(HypervisorArn=ghost_arn))
    assert ghost == ("AccessDeniedException", MAPPINGS_NOT_CONFIGURED), (
        f"the access-denied gate must fire before resource-existence lookup for a nonexistent "
        f"HypervisorArn, got {ghost!r}"
    )

    malformed_arn = "not-an-arn-" + "x" * 45
    malformed = _client_error(
        lambda: bg.start_virtual_machines_metadata_sync(HypervisorArn=malformed_arn)
    )
    assert malformed == ("ValidationException", _arn_pattern_message(malformed_arn)), (
        f"a syntactically malformed HypervisorArn must be caught by format validation before "
        f"the access-denied gate, got {malformed!r}"
    )

    before = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert not before.get("LatestMetadataSyncStatus"), (
        f"a freshly imported hypervisor must start with no sync status, got "
        f"{before.get('LatestMetadataSyncStatus')!r}"
    )

    got = _client_error(lambda: bg.start_virtual_machines_metadata_sync(HypervisorArn=arn))
    assert got == ("AccessDeniedException", MAPPINGS_NOT_CONFIGURED), (
        f"expected AccessDeniedException for a hypervisor with no property mappings configured, "
        f"got {got!r}"
    )

    # Rejected synchronously: no state transition was recorded on the hypervisor.
    after = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert not after.get("LatestMetadataSyncStatus"), (
        f"a synchronously rejected sync must not record any status, got "
        f"{after.get('LatestMetadataSyncStatus')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
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
    arn = bg.import_hypervisor_configuration(
        Tags=[{"Key": "sim2real-owner", "Value": "check_start_metadata_sync_state_transition"}],
        **kwargs,
    )["HypervisorArn"]

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
