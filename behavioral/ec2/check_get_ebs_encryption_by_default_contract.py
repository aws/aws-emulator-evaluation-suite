"""op-contract-get-ebs-encryption-by-default."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-ebs-encryption-by-default"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """GetEbsEncryptionByDefault reflects real toggles made via Enable/Disable
    EbsEncryptionByDefault, and honors DryRun as a distinct error boundary."""
    ec2 = ctx.client("ec2")

    initial = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]

    def _restore():
        if initial:
            ec2.enable_ebs_encryption_by_default()
        else:
            ec2.disable_ebs_encryption_by_default()

    ctx.on_cleanup(_restore)

    if initial:
        ec2.disable_ebs_encryption_by_default()
        expected = False
    else:
        ec2.enable_ebs_encryption_by_default()
        expected = True

    resp = ec2.get_ebs_encryption_by_default()
    assert resp["EbsEncryptionByDefault"] == expected, (
        f"expected EbsEncryptionByDefault={expected} after toggling, got {resp['EbsEncryptionByDefault']}"
    )

    # Flip back explicitly (in addition to the cleanup) and verify the reverse transition too.
    if expected:
        ec2.disable_ebs_encryption_by_default()
    else:
        ec2.enable_ebs_encryption_by_default()
    resp2 = ec2.get_ebs_encryption_by_default()
    assert resp2["EbsEncryptionByDefault"] == initial, (
        f"expected EbsEncryptionByDefault={initial} after reverse toggle, got {resp2['EbsEncryptionByDefault']}"
    )

    code, message = _error(lambda: ec2.get_ebs_encryption_by_default(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {message!r}"

    # DryRun must not have side effects: the setting must still read as `initial`.
    resp3 = ec2.get_ebs_encryption_by_default()
    assert resp3["EbsEncryptionByDefault"] == initial, (
        f"DryRun must not change state; expected {initial}, got {resp3['EbsEncryptionByDefault']}"
    )


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
