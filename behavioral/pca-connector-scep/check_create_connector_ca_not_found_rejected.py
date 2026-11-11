"""create-connector-ca-not-found-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-connector-ca-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector rejects a syntactically valid but nonexistent CertificateAuthorityArn
    with ResourceNotFoundException, and no connector resource is left behind; a real CA still
    lets CreateConnector succeed."""
    scep = ctx.client("pca-connector-scep")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_ca_arn = (
        f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority/{uuid.uuid4()}"
    )

    error = _client_error(lambda: scep.create_connector(CertificateAuthorityArn=bogus_ca_arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')!r}"
    )
    expected_message = f"CertificateAuthorityArn was not found: {bogus_ca_arn}."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # No connector should have been created for the bogus CA.
    listed = scep.list_connectors(MaxResults=1000)["Connectors"]
    assert not any(c["CertificateAuthorityArn"] == bogus_ca_arn for c in listed), (
        f"a connector referencing the rejected bogus CA {bogus_ca_arn} appeared in ListConnectors"
    )

    # Positive control: a real, existing, ACTIVE private CA is accepted.
    ca_arn = _create_active_ca(ctx)
    resp = scep.create_connector(
        CertificateAuthorityArn=ca_arn,
        Tags={"sim2real-check": CHECK},
    )
    connector_arn = resp["ConnectorArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_connector(scep, connector_arn))
    assert connector_arn, "CreateConnector against a real, ACTIVE CA returned no ConnectorArn"

    # Independent read at the destination: the connector genuinely exists there, linked to the
    # real CA -- not merely echoed back by the mutating call's own response.
    fetched = scep.get_connector(ConnectorArn=connector_arn)["Connector"]
    assert fetched["CertificateAuthorityArn"] == ca_arn, (
        f"expected GetConnector CertificateAuthorityArn {ca_arn}, got {fetched['CertificateAuthorityArn']}"
    )
    assert fetched["Arn"] == connector_arn, (
        f"expected GetConnector Arn {connector_arn}, got {fetched['Arn']}"
    )


from botocore.exceptions import ClientError  # noqa: E402
import time  # noqa: E402


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_pending_ca(ctx):
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    return ca_arn


def _create_active_ca(ctx):
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_pending_ca(ctx)
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


def _best_effort_delete_connector(scep, connector_arn):
    try:
        scep.delete_connector(ConnectorArn=connector_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
