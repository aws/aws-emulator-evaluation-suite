"""delete-policy-on-disabled-ca-is-noop."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-on-disabled-ca-is-noop"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a DISABLED CA, DeletePolicy with no policy attached succeeds as a no-op and a policy put
    while DISABLED can be deleted; only a CA ARN that names no CA is ResourceNotFoundException.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_DeletePolicy.html"""
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

    code, message = _error(lambda: client.get_policy(ResourceArn=ca_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException before any policy exists, got {code!r}"
    assert message == _NO_POLICY_MESSAGE, message

    client.delete_policy(ResourceArn=ca_arn)
    code, message = _error(lambda: client.get_policy(ResourceArn=ca_arn))
    assert code == "ResourceNotFoundException", f"expected DeletePolicy no-op to leave no policy behind, got {code!r}"
    assert message == _NO_POLICY_MESSAGE, message

    policy_doc = _resource_policy(ca_arn, own_account_id)
    client.put_policy(ResourceArn=ca_arn, Policy=policy_doc)
    attached = client.get_policy(ResourceArn=ca_arn)["Policy"]
    attached_sid = json.loads(attached)["Statement"][0]["Sid"]
    assert attached_sid == "sim2realacmpcashare", f"expected Sid 'sim2realacmpcashare', got {attached_sid!r}"

    client.delete_policy(ResourceArn=ca_arn)
    code, message = _error(lambda: client.get_policy(ResourceArn=ca_arn))
    assert code == "ResourceNotFoundException", f"expected the attached policy to be gone after DeletePolicy, got {code!r}"
    assert message == _NO_POLICY_MESSAGE, message

    bogus_arn = ca_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: client.delete_policy(ResourceArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"unexpected code={code!r}"
    assert message == "Could not find specified CA", message


_NO_POLICY_MESSAGE = "Could not find policy for specified resource."


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; a success is a mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, it succeeded")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _resource_policy(ca_arn, own_account_id):
    # AWS Private CA rejects a nonexistent account Principal ("Principal not found"), so use the
    # documented Organizations-sharing shape: wildcard Principal scoped by conditions.
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
        Tags=[{"Key": "sim2real-check", "Value": "delete-policy-on-disabled-ca-is-noop"}],
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
    """Activate a new ROOT CA: self-sign its CSR with the RootCACertificate/V1 template and
    import the result."""
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
