"""op-contract-disable-ebs-encryption-by-default."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-ebs-encryption-by-default"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """DisableEbsEncryptionByDefault: flips the account/Region default-encryption
    setting to False and asserts it sticks via GetEbsEncryptionByDefault, restoring the
    original setting afterwards; plus the DryRun permission-check contract."""
    ec2 = ctx.client("ec2")

    original = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]

    def _restore():
        if original:
            ec2.enable_ebs_encryption_by_default()
        else:
            ec2.disable_ebs_encryption_by_default()

    ctx.on_cleanup(_restore)

    # Drive it to enabled first so the disable call is a real transition, not a no-op.
    ec2.enable_ebs_encryption_by_default()
    enabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert enabled is True, f"expected EbsEncryptionByDefault=True after enabling, got {enabled!r}"

    disable_resp = ec2.disable_ebs_encryption_by_default()
    assert disable_resp["EbsEncryptionByDefault"] is False, (
        f"DisableEbsEncryptionByDefault response reported "
        f"{disable_resp['EbsEncryptionByDefault']!r}, expected False"
    )
    disabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert disabled is False, f"expected EbsEncryptionByDefault=False after disabling, got {disabled!r}"

    code, message = _error(lambda: ec2.disable_ebs_encryption_by_default(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    # DryRun must not have changed anything.
    still_disabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert still_disabled is False, (
        f"DryRun disable call changed the setting: expected False, got {still_disabled!r}"
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
