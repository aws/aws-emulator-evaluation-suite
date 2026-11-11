"""create-challenge-returns-password-and-metadata."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "create-challenge-returns-password-and-metadata"
GROUP = "data-plane"
SERVICES = ["pca-connector-scep"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChallenge returns a well-formed UUID password bound to the connector, and
    GetChallengePassword / GetChallengeMetadata surface the same values afterwards."""
    creator = _scep_creator_client(ctx)
    ca_arn = _create_root_ca(ctx)
    _share_ca_with_scep_connector(ctx, ca_arn)
    connector_arn = _create_connector(ctx, ca_arn, creator)
    connector = _wait_connector_status(ctx, connector_arn, {"ACTIVE", "FAILED"}, timeout_s=240)
    if connector["Status"] != "ACTIVE":
        raise AssertionError(
            f"expected connector to reach ACTIVE, got {connector['Status']} "
            f"reason={connector.get('StatusReason')}"
        )

    scep = ctx.client("pca-connector-scep")
    created = scep.create_challenge(ConnectorArn=connector_arn, ClientToken=str(uuid.uuid4()))[
        "Challenge"
    ]
    challenge_arn = created["Arn"]
    password = created["Password"]

    assert created["ConnectorArn"] == connector_arn, (
        f"expected challenge ConnectorArn {connector_arn!r}, got {created['ConnectorArn']!r}"
    )
    assert challenge_arn.startswith(connector_arn + "/challenge/"), (
        f"expected challenge Arn under {connector_arn + '/challenge/'!r}, got {challenge_arn!r}"
    )
    uuid.UUID(password)  # raises ValueError if not a valid UUID

    fetched_password = scep.get_challenge_password(ChallengeArn=challenge_arn)["Password"]
    assert fetched_password == password, (
        f"expected GetChallengePassword to return the CreateChallenge password {password!r}, "
        f"got {fetched_password!r}"
    )

    metadata = scep.get_challenge_metadata(ChallengeArn=challenge_arn)["ChallengeMetadata"]
    assert metadata["Arn"] == challenge_arn, (
        f"expected challenge metadata Arn {challenge_arn!r}, got {metadata['Arn']!r}"
    )
    assert metadata["ConnectorArn"] == connector_arn, (
        f"expected challenge metadata ConnectorArn {connector_arn!r}, got {metadata['ConnectorArn']!r}"
    )
    assert "CreatedAt" in metadata and "UpdatedAt" in metadata, (
        f"expected CreatedAt and UpdatedAt in challenge metadata, got keys {sorted(metadata)}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402


_SCEP_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "pca-connector-scep:CreateConnector",
                    "pca-connector-scep:ListConnectors",
                    "pca-connector-scep:TagResource",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "acm-pca:DescribeCertificateAuthority",
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:ListCertificateAuthorities",
                    "acm-pca:ListTags",
                    "acm-pca:PutPolicy",
                ],
                "Resource": "*",
            },
            {
                # Connector for SCEP issues its certificate with the CreateConnector caller's
                # permissions, only for this template and only through the service.
                "Effect": "Allow",
                "Action": "acm-pca:IssueCertificate",
                "Resource": "*",
                "Condition": {
                    "ArnLike": {
                        "acm-pca:TemplateArn": (
                            "arn:aws:acm-pca:::template/BlankEndEntityCertificate_APICSRPassthrough/V*"
                        )
                    },
                    "ForAnyValue:StringEquals": {"aws:CalledVia": "pca-connector-scep.amazonaws.com"},
                },
            },
        ],
    }
)
_CREATOR_POLICY = "scep-creator"

_SCEP_RAM_PERMISSION_ARN = (
    "arn:aws:ram::aws:permission/"
    "AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority"
)


def _scep_creator_client(ctx):
    """A role the check creates and deletes, holding the permissions Connector for SCEP needs from
    the CreateConnector caller to issue the connector's certificate (docs.aws.amazon.com/privateca/
    latest/userguide/connector-for-scep-setting-up.html); returns a client that calls as that role."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-scep-creator-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_creator_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_CREATOR_POLICY, PolicyDocument=_SCEP_POLICY_DOC
    )
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    left = ctx.time_left()
    deadline = time.monotonic() + (90.0 if left is None else min(90.0, left))
    creator = None
    while True:
        try:
            if creator is None:
                creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="scep-creator")["Credentials"]
                creator = ctx.client(
                    "pca-connector-scep",
                    creds={
                        "aws_access_key_id": creds["AccessKeyId"],
                        "aws_secret_access_key": creds["SecretAccessKey"],
                        "aws_session_token": creds["SessionToken"],
                    },
                )
            creator.list_connectors(MaxResults=1)
            return creator
        except ClientError as exc:
            # IAM propagation: the new role and its policy are refused until they take effect.
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDenied", "AccessDeniedException") or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _delete_creator_role(iam, role_name):
    """Delete the role's inline policy, then the role; NoSuchEntity means it is already gone."""
    for delete in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_CREATOR_POLICY),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _share_ca_with_scep_connector(ctx, ca_arn):
    """CreateConnector calls acm-pca on your behalf via the pca-connector-scep.amazonaws.com
    service principal, which has no access to a private CA until you explicitly share it --
    an AWS RAM resource share is a hard prerequisite for programmatic (non-console) use, not
    merely an IAM grant (see Step 3, docs.aws.amazon.com/privateca/latest/userguide/
    connector-for-scep-setting-up.html). Without it CreateConnector still succeeds but the
    connector transitions to FAILED/PRIVATECA_ACCESS_DENIED."""
    ram = ctx.client("ram")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    share_name = ctx.unique_name("sim2real-scep-share-")
    resp = ram.create_resource_share(
        name=share_name,
        resourceArns=[ca_arn],
        principals=["pca-connector-scep.amazonaws.com"],
        permissionArns=[_SCEP_RAM_PERMISSION_ARN],
        sources=[account_id],
    )
    share_arn = resp["resourceShare"]["resourceShareArn"]

    def _cleanup():
        try:
            ram.delete_resource_share(resourceShareArn=share_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UnknownResourceException":
                raise

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: ram.get_resource_share_associations(
            associationType="RESOURCE", resourceShareArns=[share_arn]
        )["resourceShareAssociations"],
        lambda assocs: bool(assocs) and assocs[0]["status"] == "ASSOCIATED",
        timeout_s=60,
        interval_s=2,
    )
    return share_arn


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
        Tags=[{"Key": "sim2real-check", "Value": "create-challenge-returns-password-and-metadata"}],
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


def _create_connector(ctx, ca_arn, creator, **kwargs):
    scep = ctx.client("pca-connector-scep")
    resp = creator.create_connector(
        CertificateAuthorityArn=ca_arn,
        Tags={"sim2real-check": "create-challenge-returns-password-and-metadata"},
        **kwargs,
    )
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
