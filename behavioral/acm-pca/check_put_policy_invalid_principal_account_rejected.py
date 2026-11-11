"""put-policy-invalid-principal-account-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-policy-invalid-principal-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy naming a nonexistent account as Principal fails with InvalidPolicyException and
    attaches nothing, even on a DISABLED CA; a valid Organizations-sharing policy is accepted
    while DISABLED and stays attached after the CA is re-enabled."""
    client = ctx.client("acm-pca")
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    ca_arn = _create_root_ca(ctx, client)
    ctx.on_cleanup(lambda: _teardown_ca(client, ca_arn))
    _activate_root_ca(client, ca_arn)

    client.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    _poll_until(
        lambda: client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "DISABLED",
        timeout_s=60,
    )

    # Negative: PutPolicy naming a nonexistent AWS account as Principal is rejected --
    # AWS Private CA validates principal existence, regardless of CA state.
    bogus_principal_policy = _account_principal_policy("999999999999", ca_arn)
    code, message = _error(lambda: client.put_policy(ResourceArn=ca_arn, Policy=bogus_principal_policy))
    assert code == "InvalidPolicyException", f"unexpected code={code!r}"
    assert message == "InvalidPolicy: Principal not found.", f"unexpected message={message!r}"

    # Effect absent: no policy was attached by the rejected call.
    code, message = _error(lambda: client.get_policy(ResourceArn=ca_arn))
    assert code == "ResourceNotFoundException", f"expected no policy attached, got code={code!r}"
    assert message == "Could not find policy for specified resource.", f"unexpected message={message!r}"

    # Positive control: a validly-shaped policy (Organizations wildcard form) is
    # accepted on the SAME CA while still DISABLED -- proving the earlier rejection was
    # about policy content, not CA state.
    valid_policy = _org_sharing_policy(ca_arn, own_account_id)
    client.put_policy(ResourceArn=ca_arn, Policy=valid_policy)
    attached = client.get_policy(ResourceArn=ca_arn)["Policy"]
    attached_sid = json.loads(attached)["Statement"][0]["Sid"]
    assert attached_sid == "sim2realacmpcashare", f"expected sim2realacmpcashare, got {attached_sid!r}"

    # Re-enable the same CA; the same policy remains attached and usable.
    client.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="ACTIVE")
    _poll_until(
        lambda: client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
    )
    attached_after = client.get_policy(ResourceArn=ca_arn)["Policy"]
    attached_after_sid = json.loads(attached_after)["Statement"][0]["Sid"]
    assert attached_after_sid == "sim2realacmpcashare", f"expected sim2realacmpcashare, got {attached_after_sid!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _account_principal_policy(account_id, ca_arn):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": [
                        "acm-pca:DescribeCertificateAuthority",
                        "acm-pca:GetCertificate",
                        "acm-pca:GetCertificateAuthorityCertificate",
                        "acm-pca:ListPermissions",
                        "acm-pca:ListTags",
                    ],
                    "Resource": ca_arn,
                }
            ],
        }
    )


def _org_sharing_policy(ca_arn, own_account_id):
    # AWS Private CA validates that an AWS-account Principal actually exists, so a
    # synthetic 12-digit account id is rejected with InvalidPolicyException ("Principal
    # not found"). Use the documented Organizations-sharing shape (wildcard Principal
    # scoped by PrincipalOrgID/PrincipalAccount conditions) instead, which does not
    # require a real external account.
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "sim2realacmpcashare",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": [
                        "acm-pca:DescribeCertificateAuthority",
                        "acm-pca:GetCertificate",
                        "acm-pca:GetCertificateAuthorityCertificate",
                        "acm-pca:ListPermissions",
                        "acm-pca:ListTags",
                    ],
                    "Resource": ca_arn,
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4z5"},
                        "StringNotEquals": {"aws:PrincipalAccount": own_account_id},
                    },
                }
            ],
        }
    )


def _create_root_ca(ctx, client):
    name = ctx.unique_name("sim2real-acmpca-")
    resp = client.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": name},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    return resp["CertificateAuthorityArn"]


def _try_get_csr(client, ca_arn):
    try:
        return client.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    except client.exceptions.RequestInProgressException:
        return None


def _try_get_certificate(client, ca_arn, cert_arn):
    try:
        return client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
    except client.exceptions.RequestInProgressException:
        return None


def _activate_root_ca(client, ca_arn):
    """Drive a freshly created ROOT CA from PENDING_CERTIFICATE to ACTIVE by having the
    CA self-sign its own CSR via IssueCertificate + the RootCACertificate/V1 template,
    then importing the resulting certificate -- the documented CLI activation flow."""
    _poll_until(
        lambda: client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "PENDING_CERTIFICATE",
        timeout_s=60,
    )
    csr = _poll_until(lambda: _try_get_csr(client, ca_arn), lambda v: v is not None, timeout_s=60)
    issued = client.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )
    cert_arn = issued["CertificateArn"]
    cert_pem = _poll_until(
        lambda: _try_get_certificate(client, ca_arn, cert_arn),
        lambda v: v is not None,
        timeout_s=60,
    )
    client.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=cert_pem)
    _poll_until(
        lambda: client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
    )


def _teardown_ca(client, ca_arn):
    try:
        status = client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "ACTIVE":
        client.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(
            lambda: client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
                "CertificateAuthority"
            ]["Status"],
            lambda s: s == "DISABLED",
            timeout_s=60,
        )
        status = "DISABLED"
    if status != "DELETED":
        client.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
