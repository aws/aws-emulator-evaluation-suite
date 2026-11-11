"""get-console-screenshot-invalid-instance-rejected-dup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-console-screenshot-invalid-instance-rejected-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConsoleScreenshot with DryRun on a made-up instance id fails DryRunOperation, and the real
    call fails InvalidInstanceID.Malformed, each with its exact message.
    """
    ec2 = ctx.client("ec2")
    bogus_instance_id = "i-0123456789abcdef0"

    # Success-path contract proxy: DryRun proves the request is well-formed and
    # authorized, independent of whether the instance actually exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.get_console_screenshot(InstanceId=bogus_instance_id, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dry_run_message!r}"

    # Error boundary: without DryRun, a made-up instance id must be rejected.
    code, message = _error(lambda: ec2.get_console_screenshot(InstanceId=bogus_instance_id))
    assert code == "InvalidInstanceID.Malformed", f"expected InvalidInstanceID.Malformed, got {code!r}"
    assert message == f"The instance ID '{bogus_instance_id}' is malformed", f"unexpected InvalidInstanceID.Malformed message {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
