"""create-challenge-on-inactive-connector-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "create-challenge-on-inactive-connector-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-scep"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CreateConnector caller without acm-pca:IssueCertificate leaves the connector FAILED with
    PRIVATECA_ACCESS_DENIED; CreateChallenge and ListChallengeMetadata on it get ValidationException, on
    a nonexistent ARN ResourceNotFoundException (exact messages)."""
    ca_arn = _create_root_ca(ctx, activate=True)
    creator = _scep_creator_client(ctx)
    connector_arn = _create_connector(ctx, ca_arn, creator)
    failed = _wait_connector_status(ctx, connector_arn, {"ACTIVE", "FAILED"}, timeout_s=240)
    assert failed["Status"] == "FAILED", (
        f"expected FAILED without acm-pca:IssueCertificate, got {failed['Status']!r} "
        f"(reason={failed.get('StatusReason')!r})"
    )
    assert failed.get("StatusReason") == "PRIVATECA_ACCESS_DENIED", failed.get("StatusReason")

    scep = ctx.client("pca-connector-scep")
    error = _client_error(
        lambda: scep.create_challenge(ConnectorArn=connector_arn, ClientToken=str(uuid.uuid4()))
    )
    _assert_error(
        error,
        ("ValidationException", f"Validation error detected: Resource(s) are not active: {connector_arn}."),
    )

    listed_error = _client_error(lambda: scep.list_challenge_metadata(ConnectorArn=connector_arn))
    _assert_error(
        listed_error,
        ("ValidationException", f"Validation error detected: Resource cannot be in state FAILED: {connector_arn}."),
    )

    _assert_rejection_is_state_specific(ctx)


def _assert_rejection_is_state_specific(ctx):
    """Positive control: a nonexistent connector is rejected with a *different* code than a
    not-ACTIVE one, so "not ACTIVE -> ValidationException" isn't indistinguishable from
    "CreateChallenge/ListChallengeMetadata reject every call regardless of connector state"."""
    scep = ctx.client("pca-connector-scep")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_connector_arn = (
        f"arn:aws:pca-connector-scep:{ctx.region}:{account}:connector/{uuid.uuid4()}"
    )

    error = _client_error(
        lambda: scep.create_challenge(
            ConnectorArn=bogus_connector_arn, ClientToken=str(uuid.uuid4())
        )
    )
    _assert_error(
        error, ("ResourceNotFoundException", f"ConnectorArn was not found: {bogus_connector_arn}.")
    )

    listed_error = _client_error(
        lambda: scep.list_challenge_metadata(ConnectorArn=bogus_connector_arn)
    )
    _assert_error(
        listed_error, ("ResourceNotFoundException", f"Connector was not found: {bogus_connector_arn}.")
    )


from botocore.exceptions import ClientError  # noqa: E402


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_error(error, expected):
    assert error.get("Code") == expected[0], f"expected {expected[0]}, got {error.get('Code')!r}"
    assert error.get("Message") == expected[1], (
        f"expected message {expected[1]!r}, got {error.get('Message')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
                # No acm-pca:IssueCertificate: Connector for SCEP issues its certificate with the
                # CreateConnector caller's permissions, so provisioning fails with PRIVATECA_ACCESS_DENIED.
                "Effect": "Allow",
                "Action": [
                    "acm-pca:DescribeCertificateAuthority",
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:ListCertificateAuthorities",
                    "acm-pca:ListTags",
                ],
                "Resource": "*",
            },
        ],
    }
)
_CREATOR_POLICY = "scep-creator"


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
            # IAM propagation: the new role and its policy are refused, and a fresh session token is
            # reported invalid, until they take effect; an invalid token is re-assumed.
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDenied", "AccessDeniedException", "UnrecognizedClientException"):
                raise
            if time.monotonic() > deadline:
                raise
            if code == "UnrecognizedClientException":
                creator = None
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
