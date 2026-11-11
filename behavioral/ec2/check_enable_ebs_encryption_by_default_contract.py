"""enable-ebs-encryption-by-default-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "enable-ebs-encryption-by-default-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """EnableEbsEncryptionByDefault flips the account/Region default to encrypted, the
    change is observable via GetEbsEncryptionByDefault, and a DryRun call is rejected with
    DryRunOperation without applying the change."""
    ec2 = ctx.client("ec2")

    original = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]

    def _restore():
        if original:
            ec2.enable_ebs_encryption_by_default()
        else:
            ec2.disable_ebs_encryption_by_default()

    ctx.on_cleanup(_restore)

    # Drive it to disabled first so the DryRun enable below is a real transition test, not a
    # no-op that would pass even if DryRun silently applied the change.
    ec2.disable_ebs_encryption_by_default()
    before_dry_run = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert before_dry_run is False, f"expected disabled before DryRun test, got {before_dry_run}"

    # NEGATIVE: DryRun must not apply the change.
    code, message = _error(lambda: ec2.enable_ebs_encryption_by_default(DryRun=True))
    assert code == "DryRunOperation", f"unexpected DryRun error code: {code}"
    assert message == DRY_RUN_MESSAGE, f"unexpected DryRun message: {message!r}"

    after_dry_run = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert after_dry_run is False, (
        f"DryRun call applied the change: expected False, got {after_dry_run}"
    )

    # POSITIVE: the real call applies and is observable.
    resp = ec2.enable_ebs_encryption_by_default()
    assert resp["EbsEncryptionByDefault"] is True, (
        f"expected EnableEbsEncryptionByDefault to report True, got {resp['EbsEncryptionByDefault']}"
    )

    described = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    assert described is True, f"expected GetEbsEncryptionByDefault to report True, got {described}"


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
