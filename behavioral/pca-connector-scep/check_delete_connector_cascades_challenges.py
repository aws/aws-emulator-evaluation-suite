"""delete-connector-cascades-challenges."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delete-connector-cascades-challenges"
GROUP = "state-machine"
SERVICES = ["pca-connector-scep"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnector removes the connector and all of its associated Challenges; the
    challenges become unreachable (ResourceNotFoundException) once the deletion completes,
    and a DeleteChallenge on a removed challenge is an idempotent success."""
    ca_arn = _create_root_ca(ctx)
    _share_ca_with_scep(ctx, ca_arn)
    scep = ctx.client("pca-connector-scep")
    connector_arn = _create_connector(ctx, scep, ca_arn)
    connector = _poll_until(
        lambda: scep.get_connector(ConnectorArn=connector_arn)["Connector"],
        lambda c: c["Status"] in ("ACTIVE", "FAILED"),
        timeout_s=240,
        interval_s=3.0,
    )
    assert connector["Status"] == "ACTIVE", (
        f"expected connector to reach ACTIVE, got {connector['Status']} reason={connector.get('StatusReason')}"
    )
    challenge_arns = []
    for _ in range(2):
        resp = scep.create_challenge(ConnectorArn=connector_arn, ClientToken=str(uuid.uuid4()))
        challenge_arns.append(resp["Challenge"]["Arn"])

    scep.delete_connector(ConnectorArn=connector_arn)

    def _connector_gone():
        try:
            scep.get_connector(ConnectorArn=connector_arn)
        except ClientError as e:
            return e.response["Error"]["Code"]
        return "present"

    _poll_until(_connector_gone, lambda c: c == "ResourceNotFoundException", timeout_s=120)
    gone = _error(lambda: scep.get_connector(ConnectorArn=connector_arn))
    assert gone == ("ResourceNotFoundException", f"Connector was not found: {connector_arn}."), gone

    for arn in challenge_arns:
        not_found = ("ResourceNotFoundException", f"Challenge was not found: {arn}.")
        meta = _error(lambda a=arn: scep.get_challenge_metadata(ChallengeArn=a))
        assert meta == not_found, f"GetChallengeMetadata: expected {not_found!r}, got {meta!r}"
        pw = _error(lambda a=arn: scep.get_challenge_password(ChallengeArn=a))
        assert pw == not_found, f"GetChallengePassword: expected {not_found!r}, got {pw!r}"
        # DeleteChallenge on a challenge the cascade already removed is an idempotent success,
        # and the challenge stays unreadable afterwards.
        scep.delete_challenge(ChallengeArn=arn)
        again = _error(lambda a=arn: scep.get_challenge_metadata(ChallengeArn=a))
        assert again == not_found, f"GetChallengeMetadata after DeleteChallenge: expected {not_found!r}, got {again!r}"


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


def _create_connector(ctx, scep, ca_arn) -> str:
    arn = scep.create_connector(CertificateAuthorityArn=ca_arn, Tags={"sim2real-check": CHECK})["ConnectorArn"]

    def _cleanup():
        try:
            scep.delete_connector(ConnectorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
