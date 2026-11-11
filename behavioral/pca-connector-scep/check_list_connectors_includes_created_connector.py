"""list-connectors-includes-created-connector."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-connectors-includes-created-connector"
GROUP = "control-plane"
SERVICES = ["pca-connector-scep"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnectors' paginated result set includes a just-created connector with attributes
    (CertificateAuthorityArn, Type, Status) matching what GetConnector reports for it."""
    ca_arn = _create_root_ca(ctx, activate=True)
    connector_arn = _create_connector(ctx, ca_arn)

    scep = ctx.client("pca-connector-scep")
    # The connector settles out of CREATING first, so the listed and the direct Status are compared
    # on a state that no longer moves.
    left = ctx.time_left()
    try:
        _poll_until(
            lambda: scep.get_connector(ConnectorArn=connector_arn)["Connector"]["Status"],
            lambda status: status in ("ACTIVE", "FAILED"),
            timeout_s=120.0 if left is None else max(1.0, min(120.0, left - 5.0)),
        )
    except AssertionError:
        left = ctx.time_left()
        if left is not None and left <= 6.0:
            raise TimeoutError("connector leaving CREATING: the run budget ended first; not graded")
        raise
    found = None
    next_token = None
    for _ in range(50):
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = scep.list_connectors(**kwargs)
        for c in resp["Connectors"]:
            if c["Arn"] == connector_arn:
                found = c
                break
        if found or not resp.get("NextToken"):
            break
        next_token = resp["NextToken"]

    assert found is not None, "created connector did not appear in ListConnectors"
    assert found["CertificateAuthorityArn"] == ca_arn, (
        f"expected CertificateAuthorityArn {ca_arn!r}, got {found['CertificateAuthorityArn']!r}"
    )
    assert found["Type"] == "GENERAL_PURPOSE", (
        f"expected Type GENERAL_PURPOSE (no MobileDeviceManagement supplied), got {found['Type']!r}"
    )

    direct = scep.get_connector(ConnectorArn=connector_arn)["Connector"]
    assert found["Status"] == direct["Status"], (
        f"ListConnectors Status {found['Status']!r} disagrees with GetConnector Status "
        f"{direct['Status']!r} for the same connector"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    kwargs.setdefault("Tags", {"sim2real": CHECK})
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
