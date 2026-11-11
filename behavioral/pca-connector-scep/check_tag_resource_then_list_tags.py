"""tag-resource-then-list-tags."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "tag-resource-then-list-tags"
GROUP = "tagging"
SERVICES = ["pca-connector-scep"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a connector and ListTagsForResource reflects them exactly."""
    ca_arn = _create_root_ca(ctx, activate=True)
    connector_arn = _create_connector(ctx, ca_arn)

    scep = ctx.client("pca-connector-scep")
    scep.tag_resource(
        ResourceArn=connector_arn, Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"}
    )

    tags = scep.list_tags_for_resource(ResourceArn=connector_arn)["Tags"]
    assert tags.get("sim2real-env") == "test", (
        f"expected sim2real-env=test, got {tags.get('sim2real-env')!r} (tags={tags!r})"
    )
    assert tags.get("sim2real-owner") == "behavioral", (
        f"expected sim2real-owner=behavioral, got {tags.get('sim2real-owner')!r} (tags={tags!r})"
    )


from botocore.exceptions import ClientError  # noqa: E402


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_root_ca(ctx, activate=True):
    acmpca = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-scep-ca-")[:60]
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType="ROOT",
        IdempotencyToken=uuid.uuid4().hex[:32],
    )
    ca_arn = resp["CertificateAuthorityArn"]

    def _cleanup():
        try:
            acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            acmpca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s in ("PENDING_CERTIFICATE", "ACTIVE"),
        timeout_s=60,
        interval_s=2,
    )

    if activate:
        csr = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        issued = acmpca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
            Validity={"Value": 10, "Type": "YEARS"},
        )
        cert_arn = issued["CertificateArn"]

        def _get_cert():
            try:
                return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "RequestInProgressException":
                    return None
                raise

        cert_resp = _poll_until(_get_cert, lambda r: r is not None, timeout_s=90, interval_s=3)
        acmpca.import_certificate_authority_certificate(
            CertificateAuthorityArn=ca_arn,
            Certificate=cert_resp["Certificate"].encode("utf-8"),
        )
        _poll_until(
            lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
                "CertificateAuthority"
            ]["Status"],
            lambda s: s == "ACTIVE",
            timeout_s=90,
            interval_s=2,
        )
    return ca_arn


def _create_connector(ctx, ca_arn, **kwargs):
    scep = ctx.client("pca-connector-scep")
    resp = scep.create_connector(CertificateAuthorityArn=ca_arn, **kwargs)
    connector_arn = resp["ConnectorArn"]

    def _cleanup():
        try:
            scep.delete_connector(ConnectorArn=connector_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return connector_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
