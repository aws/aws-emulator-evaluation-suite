"""op-contract-get-serial-console-access-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-serial-console-access-status"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSerialConsoleAccessStatus returns the account-level serial console access
    setting with a well-formed shape; DryRun surfaces the documented DryRunOperation
    error rather than performing/answering the real query."""
    ec2 = ctx.client("ec2")

    # success-path contract: a boolean flag plus a valid "managedBy" enum value.
    resp = ec2.get_serial_console_access_status()
    assert isinstance(resp["SerialConsoleAccessEnabled"], bool)
    assert resp["ManagedBy"] == "account", f"unexpected ManagedBy: {resp['ManagedBy']!r}"

    # error boundary: this account genuinely has permission, so DryRun must yield the
    # documented DryRunOperation error, distinct from UnauthorizedOperation.
    code, message = _client_error(lambda: ec2.get_serial_console_access_status(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
