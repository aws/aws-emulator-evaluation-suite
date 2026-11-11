"""delete-challenge-removes-password."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delete-challenge-removes-password"
GROUP = "state-machine"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChallenge removes the challenge: its password and metadata become unreachable and
    it no longer appears in ListChallengeMetadata for the connector."""
    creator = _scep_creator_client(ctx)
    ca_arn = _create_root_ca(ctx)
    _share_ca_with_connector(ctx, ca_arn)
    connector_arn = _create_connector(ctx, ca_arn, creator)
    connector = _wait_connector_status(ctx, connector_arn, {"ACTIVE", "FAILED"}, timeout_s=240)
    if connector["Status"] != "ACTIVE":
        raise AssertionError(
            f"expected connector to reach ACTIVE, got {connector['Status']} "
            f"reason={connector.get('StatusReason')}"
        )

    scep = ctx.client("pca-connector-scep")
    challenge_arn = scep.create_challenge(
        ConnectorArn=connector_arn, ClientToken=str(uuid.uuid4())
    )["Challenge"]["Arn"]

    scep.delete_challenge(ChallengeArn=challenge_arn)

    def _password_still_readable():
        try:
            scep.get_challenge_password(ChallengeArn=challenge_arn)
        except ClientError:
            return False
        return True

    _poll_until(_password_still_readable, lambda readable: not readable, timeout_s=90)

    expected_message = f"Challenge was not found: {challenge_arn}."
    password_error = _client_error(lambda: scep.get_challenge_password(ChallengeArn=challenge_arn))
    assert password_error.get("Code") == "ResourceNotFoundException", password_error
    assert password_error.get("Message") == expected_message, password_error

    meta_error = _client_error(lambda: scep.get_challenge_metadata(ChallengeArn=challenge_arn))
    assert meta_error.get("Code") == "ResourceNotFoundException", meta_error
    assert meta_error.get("Message") == expected_message, meta_error

    remaining = scep.list_challenge_metadata(ConnectorArn=connector_arn)["Challenges"]
    remaining_arns = {c["Arn"] for c in remaining}
    assert challenge_arn not in remaining_arns, (
        f"deleted challenge {challenge_arn} still listed in {remaining_arns}"
    )

    # Measured, not assumed: DeleteChallenge on an already-deleted challenge is idempotent on
    # real AWS -- it returns 200, not ResourceNotFoundException. Any ClientError fails the check.
    scep.delete_challenge(ChallengeArn=challenge_arn)


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


def _share_ca_with_connector(ctx, ca_arn):
    """Connector for SCEP needs the private CA shared with the pca-connector-scep.amazonaws.com
    service principal via AWS RAM before CreateConnector can reach ACTIVE; the console does this
    step for you, the API does not (see connector-for-scep-setting-up.html Step 3)."""
    ram = ctx.client("ram")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resp = ram.create_resource_share(
        name=ctx.unique_name("sim2real-scep-share-"),
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
        lambda: ram.get_resource_shares(resourceShareArns=[share_arn], resourceOwner="SELF")[
            "resourceShares"
        ][0]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    return share_arn


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
    resp = creator.create_connector(CertificateAuthorityArn=ca_arn, **kwargs)
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
