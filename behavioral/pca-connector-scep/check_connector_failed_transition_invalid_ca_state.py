"""connector-failed-transition-invalid-ca-state."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "connector-failed-transition-invalid-ca-state"
GROUP = "state-machine"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector on a PENDING_CERTIFICATE private CA is rejected at once with ValidationException
    and its exact message and lists no connector for the CA, while the same call succeeds once the CA is
    ACTIVE."""
    scep = ctx.client("pca-connector-scep")

    # Positive control: CreateConnector against an already-ACTIVE CA succeeds, so a rejection
    # below can be attributed to the CA's state and not to the account being unable to create
    # connectors at all.
    control_ca_arn = _create_root_ca(ctx, activate=True)
    control_connector_arn = _create_connector(ctx, control_ca_arn)
    control_listed = scep.list_connectors(MaxResults=1000)["Connectors"]
    assert any(c["Arn"] == control_connector_arn for c in control_listed), (
        f"positive-control connector {control_connector_arn} missing from ListConnectors"
    )

    ca_arn = _create_root_ca(ctx, activate=False)  # left in PENDING_CERTIFICATE on purpose

    error = _client_error(lambda: scep.create_connector(CertificateAuthorityArn=ca_arn))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')!r}"
    )
    expected_message = f"Validation error detected: Resource(s) are not active: {ca_arn}."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    listed = scep.list_connectors(MaxResults=1000)["Connectors"]
    assert not any(c["CertificateAuthorityArn"] == ca_arn for c in listed), (
        f"a connector for the still-pending CA {ca_arn} appeared in ListConnectors"
    )

    # Restore: activate the same CA and retry the identical call -- it must now succeed.
    _activate_ca(ctx, ca_arn)
    connector_arn = _create_connector(ctx, ca_arn)
    listed_after = scep.list_connectors(MaxResults=1000)["Connectors"]
    assert any(c["Arn"] == connector_arn for c in listed_after), (
        f"connector {connector_arn} missing from ListConnectors after CA {ca_arn} became ACTIVE"
    )


from botocore.exceptions import ClientError  # noqa: E402


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected CreateConnector to be rejected, but it succeeded: {result!r}")


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
        _activate_ca(ctx, ca_arn)
    return ca_arn


def _activate_ca(ctx, ca_arn):
    acmpca = ctx.client("acm-pca")
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


def _wait_connector_status(ctx, connector_arn, statuses, timeout_s=180.0):
    scep = ctx.client("pca-connector-scep")

    def probe():
        return scep.get_connector(ConnectorArn=connector_arn)["Connector"]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=timeout_s, interval_s=3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
