"""list-permissions-invalid-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-permissions-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPermissions rejects a malformed CertificateAuthorityArn with
    ValidationException, rather than silently returning an empty permissions list
    as if the (malformed) input were simply a valid CA with no permissions granted.
    """
    acm = ctx.client("acm-pca")
    malformed_arn = "not-an-acm-pca-arn"

    def _list_with_malformed_arn():
        acm.list_permissions(CertificateAuthorityArn=malformed_arn)

    refusal = _error(_list_with_malformed_arn)
    # Empirically, real AWS rejects a malformed CertificateAuthorityArn with the
    # generic ValidationException (the ARN fails the shape's pattern constraint
    # server-side) rather than a service-specific InvalidArnException -- but it is
    # still rejected outright, not treated as a valid CA with an empty permission list.
    assert refusal == (
        "ValidationException",
        "1 validation error detected: Value at 'certificateAuthorityArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"arn:[\w+=/,.@-]+:acm-pca:[\w+=/,.@-]*:[0-9]*:[\w+=,.@-]+(/[\w+=,.@-]+)*",
    ), refusal

    # positive control: a real, well-formed CA ARN returns a (possibly empty) list, not an error
    ca_arn = _create_ca(ctx)
    resp = acm.list_permissions(CertificateAuthorityArn=ca_arn)
    assert resp["Permissions"] == [], f"expected no permissions on a fresh CA, got {resp['Permissions']}"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _create_ca(ctx, key_algorithm="RSA_2048", signing_algorithm="SHA256WITHRSA", ca_type="ROOT"):
    acm = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")
    resp = acm.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": key_algorithm,
            "SigningAlgorithm": signing_algorithm,
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType=ca_type,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    _wait_for_csr_ready(ctx, arn)
    return arn


def _delete_ca(ctx, arn):
    acm = ctx.client("acm-pca")
    try:
        acm.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_csr_ready(ctx, arn, timeout_s=90.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if status in ("PENDING_CERTIFICATE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError("CA never left CREATING state")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
