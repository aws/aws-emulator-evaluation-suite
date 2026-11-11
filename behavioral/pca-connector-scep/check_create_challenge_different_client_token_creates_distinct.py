"""create-challenge-different-client-token-creates-distinct."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "create-challenge-different-client-token-creates-distinct"
GROUP = "data-plane"
SERVICES = ["pca-connector-scep"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChallenge calls made with different ClientTokens against the same connector each
    produce a distinct Challenge with its own Arn and password."""
    ca_arn = _create_root_ca(ctx)
    _share_ca_with_scep(ctx, ca_arn)
    connector_arn = _create_connector(ctx, ca_arn)
    connector = _wait_connector_status(ctx, connector_arn, {"ACTIVE", "FAILED"}, timeout_s=240)
    if connector["Status"] != "ACTIVE":
        raise AssertionError(
            f"expected connector to reach ACTIVE, got {connector['Status']} "
            f"reason={connector.get('StatusReason')}"
        )

    scep = ctx.client("pca-connector-scep")
    first = scep.create_challenge(ConnectorArn=connector_arn, ClientToken=str(uuid.uuid4()))[
        "Challenge"
    ]
    second = scep.create_challenge(ConnectorArn=connector_arn, ClientToken=str(uuid.uuid4()))[
        "Challenge"
    ]

    assert first["Arn"] != second["Arn"], (
        f"expected distinct challenge Arns, got the same value twice: {first['Arn']!r}"
    )
    assert first["Password"] != second["Password"], (
        "expected distinct challenge passwords for distinct ClientTokens, got the same password twice"
    )

    remaining_arns = {c["Arn"] for c in scep.list_challenge_metadata(ConnectorArn=connector_arn)["Challenges"]}
    assert {first["Arn"], second["Arn"]}.issubset(remaining_arns), (
        f"expected both {{{first['Arn']!r}, {second['Arn']!r}}} in list_challenge_metadata, "
        f"got {remaining_arns!r}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402


_SCEP_RAM_PERMISSION_ARN = (
    "arn:aws:ram::aws:permission/"
    "AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority"
)


def _share_ca_with_scep(ctx, ca_arn) -> None:
    """CreateConnector is executed by the pca-connector-scep.amazonaws.com service principal,
    which needs an AWS RAM resource share granting it certificate-issuance access to the CA
    (docs.aws.amazon.com/privateca/latest/userguide/connector-for-scep-setting-up.html, Step 3).
    The share is created here and polled until it is ACTIVE."""
    ram = ctx.client("ram")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resp = ram.create_resource_share(
        name=ctx.unique_name("sim2real-scep-share-"),
        resourceArns=[ca_arn],
        principals=["pca-connector-scep.amazonaws.com"],
        # Sharing with an AWS service principal requires naming the sharing account as the
        # source, or RAM rejects the request with OperationNotPermittedException.
        sources=[account_id],
        permissionArns=[_SCEP_RAM_PERMISSION_ARN],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    share_arn = resp["resourceShare"]["resourceShareArn"]

    def _cleanup():
        try:
            ram.delete_resource_share(resourceShareArn=share_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UnknownResourceException":
                raise

    ctx.on_cleanup(_cleanup)

    def _probe():
        shares = ram.get_resource_shares(resourceShareArns=[share_arn], resourceOwner="SELF")[
            "resourceShares"
        ]
        return shares[0] if shares else None

    final = _poll_until(
        _probe,
        lambda s: s is not None and s["status"] != "PENDING",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final["status"] == "ACTIVE", f"expected the RAM share to reach ACTIVE, got {final['status']!r}"


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
    kwargs.setdefault("Tags", {"sim2real-check": CHECK})
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
