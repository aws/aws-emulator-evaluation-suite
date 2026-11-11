"""create-certificate-authority-idempotency-token-mismatch."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-certificate-authority-idempotency-token-mismatch"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing an IdempotencyToken with a different CA configuration creates a second, independent
    CA (no IdempotencyParameterMismatchException, first CA untouched), while reusing it with the
    identical configuration returns the original CA's ARN without re-creating it."""
    pca = ctx.client("acm-pca")

    token = str(uuid.uuid4()).replace("-", "")[:32]
    cn_a = ctx.unique_name("sim2real-idem-a-")[:64]
    # SHORT_LIVED_CERTIFICATE is the cheaper CA tier; this check mints two CAs.
    config_a = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": cn_a},
    }
    arn = pca.create_certificate_authority(
        CertificateAuthorityConfiguration=config_a,
        CertificateAuthorityType="ROOT",
        UsageMode="SHORT_LIVED_CERTIFICATE",
        IdempotencyToken=token,
        Tags=[{"Key": "sim2real-idem-mismatch", "Value": "a"}],
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _cleanup_ca(ctx, arn))
    _wait_for_ca_status(ctx, arn, "PENDING_CERTIFICATE")

    # same token, materially different configuration (key algorithm + subject) --
    # AWS does not raise IdempotencyParameterMismatchException here; it creates an
    # independent second CA instead.
    cn_b = ctx.unique_name("sim2real-idem-b-")[:64]
    config_b = {
        "KeyAlgorithm": "RSA_4096",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": cn_b},
    }
    arn_b = pca.create_certificate_authority(
        CertificateAuthorityConfiguration=config_b,
        CertificateAuthorityType="ROOT",
        UsageMode="SHORT_LIVED_CERTIFICATE",
        IdempotencyToken=token,
        Tags=[{"Key": "sim2real-idem-mismatch", "Value": "b"}],
    )["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _cleanup_ca(ctx, arn_b))
    _wait_for_ca_status(ctx, arn_b, "PENDING_CERTIFICATE")

    assert arn_b != arn, repr((arn, arn_b))

    desc_a = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]
    assert desc_a["CertificateAuthorityConfiguration"]["Subject"]["CommonName"] == cn_a, (
        f"expected first CA's CommonName to stay {cn_a!r}, "
        f"got {desc_a['CertificateAuthorityConfiguration']['Subject'].get('CommonName')!r}"
    )
    assert desc_a["CertificateAuthorityConfiguration"]["KeyAlgorithm"] == "RSA_2048", (
        f"expected first CA's KeyAlgorithm to stay 'RSA_2048', "
        f"got {desc_a['CertificateAuthorityConfiguration']['KeyAlgorithm']!r}"
    )
    created_at_a = desc_a["CreatedAt"]

    desc_b = pca.describe_certificate_authority(CertificateAuthorityArn=arn_b)["CertificateAuthority"]
    assert desc_b["CertificateAuthorityConfiguration"]["Subject"]["CommonName"] == cn_b, (
        f"expected second CA's CommonName to be {cn_b!r}, "
        f"got {desc_b['CertificateAuthorityConfiguration']['Subject'].get('CommonName')!r}"
    )
    assert desc_b["CertificateAuthorityConfiguration"]["KeyAlgorithm"] == "RSA_4096", (
        f"expected second CA's KeyAlgorithm to be 'RSA_4096', "
        f"got {desc_b['CertificateAuthorityConfiguration']['KeyAlgorithm']!r}"
    )

    same_arn = pca.create_certificate_authority(
        CertificateAuthorityConfiguration=config_a,
        CertificateAuthorityType="ROOT",
        UsageMode="SHORT_LIVED_CERTIFICATE",
        IdempotencyToken=token,
        Tags=[{"Key": "sim2real-idem-mismatch", "Value": "a"}],
    )["CertificateAuthorityArn"]
    assert same_arn == arn, repr((same_arn, arn))

    replayed = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]
    assert replayed["CreatedAt"] == created_at_a, (
        f"replaying the same token+config changed CreatedAt from {created_at_a!r} to "
        f"{replayed['CreatedAt']!r}; the first CA was re-created rather than left alone"
    )
    matching_a = _matching_arns(pca, cn_a)
    assert matching_a == {arn}, (
        f"expected exactly one CA with CommonName {cn_a!r} after the idempotent replay, "
        f"found {len(matching_a)}: {sorted(matching_a)}"
    )


def _matching_arns(pca, common_name: str) -> set[str]:
    """ARNs of every CA, including soft-DELETED ones, whose subject CommonName is common_name."""
    found = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page.get("CertificateAuthorities", []):
            subj = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {})
            if subj.get("CommonName") == common_name:
                found.add(ca["Arn"])
    return found


def _wait_for_ca_status(ctx, arn: str, target: str, timeout_s: float = 90.0) -> None:
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last == target:
            return
        time.sleep(2)
    raise AssertionError(f"CA status never reached {target!r}, last seen {last!r}")


def _cleanup_ca(ctx, arn: str) -> None:
    pca = ctx.client("acm-pca")
    try:
        status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            pca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            _wait_for_ca_status(ctx, arn, "DISABLED", timeout_s=60.0)
        except AssertionError:
            pass
    if status != "DELETED":
        deadline = time.monotonic() + 30.0
        while True:
            try:
                pca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "InvalidStateException" and time.monotonic() <= deadline:
                    time.sleep(2)
                    continue
                raise AssertionError(
                    f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {arn} "
                    f"(last error {code!r}). It is STILL BILLING. Delete it manually: "
                    f"UpdateCertificateAuthority(Status='DISABLED') then "
                    f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
                ) from e


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
