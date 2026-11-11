"""op-contract-disable-serial-console-access."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-serial-console-access"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-serial-console-access")
def run(ctx) -> None:
    """DisableSerialConsoleAccess turns the enabled setting off, as GetSerialConsoleAccessStatus
    confirms, with the prior setting restored afterwards; DryRun answers DryRunOperation with its
    exact message and leaves it off."""
    ec2 = ctx.client("ec2")

    original = ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]

    def _restore():
        if original:
            ec2.enable_serial_console_access()
        else:
            ec2.disable_serial_console_access()

    ctx.on_cleanup(_restore)

    # Drive it to enabled first so the disable call is a real transition, not a no-op.
    ec2.enable_serial_console_access()
    status_after_enable = ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]
    assert status_after_enable is True, f"expected enabled=True after EnableSerialConsoleAccess, got {status_after_enable!r}"

    disable_resp = ec2.disable_serial_console_access()
    assert disable_resp["SerialConsoleAccessEnabled"] is False, (
        f"expected DisableSerialConsoleAccess response enabled=False, got {disable_resp['SerialConsoleAccessEnabled']!r}"
    )
    status_after_disable = ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]
    assert status_after_disable is False, f"expected enabled=False after DisableSerialConsoleAccess, got {status_after_disable!r}"

    code, message = _client_error(lambda: ec2.disable_serial_console_access(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    # DryRun must not have changed anything.
    status_after_dryrun = ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]
    assert status_after_dryrun is False, f"DryRun must not change state; expected enabled=False, got {status_after_dryrun!r}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
