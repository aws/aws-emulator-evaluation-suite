"""list-virtual-machines-empty-for-hypervisor-without-sync."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-virtual-machines-empty-for-hypervisor-without-sync"
GROUP = "state"
SERVICES = ["backup-gateway"]

HYPERVISOR_ARN_PATTERN = r"arn:(aws|aws-cn|aws-us-gov):backup-gateway(:[a-zA-Z-0-9]+){3}\/[a-zA-Z-0-9]+"


def _arn_pattern_message(value: str) -> str:
    return (
        f"1 validation error detected: Value '{value}' at 'hypervisorArn' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: {HYPERVISOR_ARN_PATTERN}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVirtualMachines returns no virtual machines for a hypervisor that has never been synced,
    and rejects a malformed HypervisorArn with ValidationException."""
    bg = ctx.client("backup-gateway")

    malformed_arn = "not-an-arn-" + "x" * 45
    malformed = code, message = _client_error(lambda: bg.list_virtual_machines(HypervisorArn=malformed_arn))
    assert code == "ValidationException", (
        f"malformed HypervisorArn: expected ValidationException, got {malformed!r}"
    )
    assert message == _arn_pattern_message(malformed_arn), (
        f"malformed HypervisorArn: expected the ARN-pattern message, got {malformed!r}"
    )

    arn = _create_hypervisor(ctx)

    resp = bg.list_virtual_machines(HypervisorArn=arn)
    got = resp.get("VirtualMachines", [])
    assert got == [], f"expected no virtual machines for an unsynced hypervisor, got {got!r}"


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
        "Tags": [{"Key": "sim2real-ephemeral", "Value": "x"}],
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
