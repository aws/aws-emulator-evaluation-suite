"""op-contract-enableSerialConsoleAccess."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableSerialConsoleAccess"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-serial-console-access")
def run(ctx) -> None:
    """EnableSerialConsoleAccess: account-level toggle contract + DryRun error boundary."""
    ec2 = ctx.client("ec2")

    original = ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]

    def _restore():
        if original:
            ec2.enable_serial_console_access()
        else:
            ec2.disable_serial_console_access()

    ctx.on_cleanup(_restore)

    resp = ec2.enable_serial_console_access()
    assert resp["SerialConsoleAccessEnabled"] is True, f"expected enabled=True in response, got {resp}"

    _poll_until(
        lambda: ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"],
        lambda v: v is True,
        timeout_s=30,
        interval_s=3,
    )

    code, message, _ = _client_error(lambda: ec2.enable_serial_console_access(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message: {message!r}"


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
