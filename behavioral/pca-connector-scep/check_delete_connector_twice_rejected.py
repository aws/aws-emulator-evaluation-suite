"""delete-connector-twice-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delete-connector-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteConnector, GetConnector gets ResourceNotFoundException "Connector was not found:
    <arn>." and a second DeleteConnector succeeds, while DeleteConnector on a Connector ARN with a
    trailing challenge segment gets ValidationException with its exact message."""
    ca_arn = _create_root_ca(ctx, activate=True)
    connector_arn = _create_connector_no_cleanup(ctx, ca_arn)

    # Wait for a terminal (non-CREATING) status before deleting, matching documented behavior
    # that DeleteConnector on a still-CREATING connector can itself raise ConflictException.
    _wait_connector_status(ctx, connector_arn, {"ACTIVE", "FAILED"}, timeout_s=180)

    scep = ctx.client("pca-connector-scep")
    scep.delete_connector(ConnectorArn=connector_arn)  # positive control: first delete succeeds

    def _still_readable():
        try:
            scep.get_connector(ConnectorArn=connector_arn)
        except ClientError:
            return False
        return True

    _poll_until(_still_readable, lambda readable: not readable, timeout_s=120)
    gone_error = _client_error(lambda: scep.get_connector(ConnectorArn=connector_arn))
    assert gone_error.get("Code") == "ResourceNotFoundException", gone_error
    assert gone_error.get("Message") == f"Connector was not found: {connector_arn}.", gone_error

    # Deleting the same (now-gone) connector again does not raise: DeleteConnector is idempotent
    # past the point of deletion, unlike GetConnector on the same ARN.
    scep.delete_connector(ConnectorArn=connector_arn)

    # A syntactically-wrong-shaped ARN (a Connector ARN with an extra Challenge segment) is
    # still rejected by input validation, proving DeleteConnector's idempotency is scoped to
    # legitimately-shaped Connector ARNs and not a blanket "never fails" behavior.
    challenge_shaped_arn = connector_arn + f"/challenge/{uuid.uuid4()}"
    bogus_error = _client_error(lambda: scep.delete_connector(ConnectorArn=challenge_shaped_arn))
    assert bogus_error.get("Code") == "ValidationException", bogus_error
    assert bogus_error.get("Message") == (
        f"1 validation error detected: Value '{challenge_shaped_arn}' at 'connectorArn' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_CONNECTOR_ARN_PATTERN}"
    ), bogus_error


from botocore.exceptions import ClientError  # noqa: E402


_CONNECTOR_ARN_PATTERN = (
    r"arn:aws(-[a-z]+)*:pca-connector-scep:[a-z]+(-[a-z]+)+-[1-9]\d*:\d{12}:connector\/"
    r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"
)


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
        Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _create_connector_no_cleanup(ctx, ca_arn, **kwargs):
    # No cleanup is registered here: the check itself deletes the connector as part of its
    # assertions, and the second (expected-to-fail) delete must not be retried by teardown.
    scep = ctx.client("pca-connector-scep")
    return scep.create_connector(
        CertificateAuthorityArn=ca_arn, Tags={"sim2real": "1"}, **kwargs
    )["ConnectorArn"]


def _wait_connector_status(ctx, connector_arn, statuses, timeout_s=180.0):
    scep = ctx.client("pca-connector-scep")

    def probe():
        return scep.get_connector(ConnectorArn=connector_arn)["Connector"]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=timeout_s, interval_s=3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
