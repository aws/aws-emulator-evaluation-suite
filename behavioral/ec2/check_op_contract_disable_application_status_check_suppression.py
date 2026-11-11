"""op-contract-disable-application-status-check-suppression."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-application-status-check-suppression"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableApplicationStatusCheckSuppression with a never-issued instance ID fails the whole call
    with InvalidInstanceID.Malformed, while the same call with DryRun answers DryRunOperation (exact
    messages)."""
    ec2 = ctx.client("ec2")
    bogus_id = "i-1234567890abcdef0"

    code, message = _error(lambda: ec2.disable_application_status_check_suppression(
        InstanceIds=[bogus_id]
    ))
    assert code == "InvalidInstanceID.Malformed", f"expected InvalidInstanceID.Malformed, got {code}"
    assert message == f"The instance ID '{bogus_id}' is malformed", (
        f"unexpected InvalidInstanceID.Malformed message: {message!r}"
    )

    code, message = _error(lambda: ec2.disable_application_status_check_suppression(
        InstanceIds=[bogus_id], DryRun=True
    ))
    assert code == "DryRunOperation", (
        f"expected the DryRun permission-check to short-circuit before instance validation, got {code}"
    )
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
