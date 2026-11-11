"""create-certificate-authority-invalid-key-algorithm-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-certificate-authority-invalid-key-algorithm-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCertificateAuthority with a KeyAlgorithm outside its enum, sent past client-side
    validation, is rejected by the service with ValidationException rather than accepted."""
    acm = ctx.client("acm-pca")
    # Bypass botocore's client-side enum validation so the invalid value is sent
    # over the wire and validated by the service itself, not rejected locally.
    acm._client_config.parameter_validation = False

    bad_cn = ctx.unique_name("sim2real-pca-badkey-")

    def _create_with_bad_key_algorithm():
        acm.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "AES_256",  # not a member of the KeyAlgorithm enum
                "SigningAlgorithm": "SHA256WITHRSA",
                "Subject": {"CommonName": bad_cn},
            },
            CertificateAuthorityType="ROOT",
        )

    code, message = _error_code(_create_with_bad_key_algorithm)
    # AWS rejects an unsupported KeyAlgorithm enum value with the
    # generic ValidationException (not a service-specific InvalidArgsException) --
    # this is still a distinct, correct-boundary rejection from the
    # invalid-signing-algorithm case's InvalidArgsException.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "Value at 'certificateAuthorityConfiguration.keyAlgorithm' failed to satisfy "
        "constraint: Member must satisfy enum value set: [RSA_2048, RSA_3072, RSA_4096, "
        "EC_prime256v1, EC_secp384r1, EC_secp521r1, ML_DSA_44, ML_DSA_65, ML_DSA_87]"
    ), f"unexpected ValidationException message: {message!r}"

    # effect absent: no CA with our unique CommonName was created by the failed call
    arns = _list_ca_arns(ctx)
    for arn in arns:
        subject = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"][
            "CertificateAuthorityConfiguration"
        ]["Subject"]
        assert subject.get("CommonName") != bad_cn, "a CA was created despite the invalid KeyAlgorithm"

    # positive control: a supported KeyAlgorithm succeeds
    good_cn = ctx.unique_name("sim2real-pca-goodkey-")
    resp = acm.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": good_cn},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    _wait_for_csr_ready(ctx, arn)
    described = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]
    actual_cn = described["CertificateAuthorityConfiguration"]["Subject"]["CommonName"]
    assert actual_cn == good_cn, f"expected CommonName {good_cn!r}, got {actual_cn!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_ca_arns(ctx, max_pages=10):
    acm = ctx.client("acm-pca")
    arns = []
    token = None
    for _ in range(max_pages):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = acm.list_certificate_authorities(**kwargs)
        arns.extend(ca["Arn"] for ca in resp.get("CertificateAuthorities", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


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
