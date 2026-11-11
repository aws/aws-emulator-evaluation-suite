"""op-contract-describe-account-vpc-encryption-control."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-account-vpc-encryption-control"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountVpcEncryptionControl returns the account-level VPC
    Encryption Control configuration object; DryRun performs the permission
    check without returning real data."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_account_vpc_encryption_control()
    control = resp["AccountVpcEncryptionControl"]
    assert isinstance(control, dict), f"expected a control object, got {control!r}"
    # the account-level control always reports a lifecycle state, even when
    # no explicit configuration has ever been applied
    assert "State" in control, f"expected a State field in {control}"
    assert control["State"] in (
        "default-state",
        "transitions-in-progress",
        "transitions-partially-successful",
        "transitions-successful",
        "transitions-failed",
    ), f"unexpected State value: {control['State']}"
    assert control.get("Mode", "unmanaged") in (
        "unmanaged",
        "attempt-monitor",
        "attempt-enforce",
    ), f"unexpected Mode value: {control.get('Mode')!r}"

    # error boundary: DryRun surfaces DryRunOperation instead of real data
    code, code_msg = _error(lambda: ec2.describe_account_vpc_encryption_control(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {code_msg!r}"
    )

    # a read (plain describe or DryRun) must not itself advance account-global
    # singleton state: re-read and require State/Mode to be unchanged
    after = ec2.describe_account_vpc_encryption_control()["AccountVpcEncryptionControl"]
    assert after["State"] == control["State"], (
        f"State advanced from a read alone: {control['State']!r} -> {after['State']!r}"
    )
    assert after.get("Mode", "unmanaged") == control.get("Mode", "unmanaged"), (
        f"Mode advanced from a read alone: {control.get('Mode')!r} -> {after.get('Mode')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
