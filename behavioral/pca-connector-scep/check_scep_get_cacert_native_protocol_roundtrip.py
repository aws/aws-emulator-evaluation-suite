"""scep-get-cacert-native-protocol-roundtrip."""
from __future__ import annotations

import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags

CHECK = "scep-get-cacert-native-protocol-roundtrip"
GROUP = "native-protocol"
SERVICES = ["pca-connector-scep"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ACTIVE connector's Endpoint answers a SCEP GetCACert request (RFC 8894) with HTTP 200 and a
    body that contains the CA certificate CreateConnector was given (same subject and serial number)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7

    creator = _scep_creator_client(ctx)
    ca_arn, ca_cert_pem = _create_root_ca(ctx)
    _share_ca_with_connector_scep(ctx, ca_arn)
    connector_arn = _create_connector(ctx, ca_arn, creator)
    connector = _wait_connector_status(ctx, connector_arn, {"ACTIVE", "FAILED"}, timeout_s=240)
    assert connector["Status"] == "ACTIVE", connector.get("StatusReason")
    endpoint = connector["Endpoint"]

    expected_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))

    def _fetch():
        target_url, route_headers = ctx.endpoint_route(f"{endpoint}?operation=GetCACert")
        req = urllib.request.Request(target_url, method="GET", headers=route_headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type", "") if e.headers else "", e.read()
        except urllib.error.URLError:
            return None

    result = _poll_until(_fetch, lambda r: r is not None and r[0] == 200, timeout_s=90, interval_s=5)
    status, content_type, body = result
    assert status == 200, f"GetCACert returned HTTP {status}"
    assert body, "GetCACert returned an empty body"

    if "ca-ra-cert" in content_type or "pkcs7" in content_type:
        served_certs = pkcs7.load_der_pkcs7_certificates(body)
    else:
        served_certs = [x509.load_der_x509_certificate(body)]

    assert any(
        c.subject == expected_cert.subject and c.serial_number == expected_cert.serial_number
        for c in served_certs
    ), "SCEP GetCACert response did not contain the connector's configured CA certificate"


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


def _share_ca_with_connector_scep(ctx, ca_arn):
    """Connector for SCEP created via the API/SDK (as opposed to the console, which does this
    step for you) requires the private CA to be shared with the pca-connector-scep service
    principal through AWS RAM -- without it CreateConnector provisions a connector that goes
    FAILED/PRIVATECA_ACCESS_DENIED (see docs.aws.amazon.com/privateca/latest/userguide/
    connector-for-scep-setting-up.html, "Step 3: Create a resource share")."""
    ram = ctx.client("ram")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resp = ram.create_resource_share(
        name=ctx.unique_name("sim2real-scep-share-"),
        resourceArns=[ca_arn],
        principals=["pca-connector-scep.amazonaws.com"],
        sources=[account_id],
        permissionArns=[
            "arn:aws:ram::aws:permission/"
            "AWSRAMBlankEndEntityCertificateAPICSRPassthroughIssuanceCertificateAuthority"
        ],
        tags=[{"key": "sim2real", "value": "scep-get-cacert-native-protocol-roundtrip"}],
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
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=3,
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


def _create_root_ca(ctx):
    """Creates and activates a root private CA, returning (ca_arn, ca_certificate_pem)."""
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
        Tags=[{"Key": "sim2real", "Value": "scep-get-cacert-native-protocol-roundtrip"}],
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
        lambda s: s == "PENDING_CERTIFICATE",
        timeout_s=60,
        interval_s=2,
    )

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
    ca_cert_pem = cert_resp["Certificate"]
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("utf-8")
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=90,
        interval_s=2,
    )
    return ca_arn, ca_cert_pem


def _create_connector(ctx, ca_arn, creator, **kwargs):
    scep = ctx.client("pca-connector-scep")
    resp = creator.create_connector(
        CertificateAuthorityArn=ca_arn,
        Tags={"sim2real": "scep-get-cacert-native-protocol-roundtrip"},
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
