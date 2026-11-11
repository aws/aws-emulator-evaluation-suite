"""op-contract-associate-enclave-certificate-iam-role."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "op-contract-associate-enclave-certificate-iam-role"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateEnclaveCertificateIamRole links an ACM certificate to an IAM role for Nitro
    Enclaves; a certificate ARN that doesn't exist is rejected."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    acm = ctx.client("acm")

    cert_arn = _self_signed_acm_cert(ctx, acm)
    role_name = ctx.unique_name("sim2real-enclave-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _wait_role_visible(iam, role_name)

    resp = _retry_until_role_arn_visible(
        lambda: ec2.associate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn),
        timeout_s=60.0,
    )
    ctx.on_cleanup(
        lambda: ec2.disassociate_enclave_certificate_iam_role(CertificateArn=cert_arn, RoleArn=role_arn)
    )
    assert resp.get("CertificateS3BucketName"), f"missing S3 bucket in response: {resp}"
    assert resp.get("CertificateS3ObjectKey"), f"missing S3 object key in response: {resp}"
    assert role_arn.split("/")[-1] in resp["CertificateS3ObjectKey"], resp["CertificateS3ObjectKey"]

    # The association can lag briefly behind the associate call's response before it's
    # visible via get_associated_enclave_certificate_iam_roles; poll a bounded window.
    #
    # Match the role ARN anywhere in the response rather than at a fixed field path.
    def _describe_role_arns():
        resp = ec2.get_associated_enclave_certificate_iam_roles(CertificateArn=cert_arn)
        return resp, _collect_strings(resp)

    associations, role_arns = _describe_role_arns()
    deadline = time.monotonic() + 120
    while role_arn not in role_arns and time.monotonic() < deadline:
        time.sleep(2)
        associations, role_arns = _describe_role_arns()
    assert role_arn in role_arns, f"association not reflected: {associations}"

    fake_cert_arn = cert_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    code, message = _error_of(lambda: ec2.associate_enclave_certificate_iam_role(CertificateArn=fake_cert_arn, RoleArn=role_arn))
    # A well-formed but nonexistent certificate ARN is rejected with the ARN-specific
    # not-found code "InvalidCertificateArn.NotFound" (matching the "Invalid<Thing>.NotFound"
    # family used elsewhere in EC2, e.g. InvalidRoleArn.NotFound above).
    assert code == "InvalidCertificateArn.NotFound", f"unexpected error code: {code}"
    assert message == "CertificateArnNotFound", message


def _collect_strings(obj) -> set:
    """Recursively gather every string value nested anywhere in a response dict/list, so
    membership checks don't depend on guessing the exact (undocumented/shape-uncertain)
    field name a describe/get response uses to carry an ARN."""
    found: set = set()
    if isinstance(obj, dict):
        for v in obj.values():
            found |= _collect_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            found |= _collect_strings(v)
    elif isinstance(obj, str):
        found.add(obj)
    return found


def _error_of(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_role_visible(iam, role_name, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except iam.exceptions.NoSuchEntityException:
            time.sleep(2)
    raise AssertionError(f"role {role_name} never became visible")


def _retry_until_role_arn_visible(fn, *, timeout_s: float, interval_s: float = 3.0):
    # A freshly created IAM role can be visible to IAM reads (get_role) well before it has
    # propagated to the EC2 control plane that validates RoleArn on this call, so a bare
    # call can transiently see InvalidRoleArn.NotFound even though the role genuinely
    # exists. Poll through that specific error for a bounded window.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleArn.NotFound" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _self_signed_acm_cert(ctx, acm) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key_path),
                "-out", str(cert_path), "-days", "1", "-nodes",
                "-subj", "/CN=sim2real-enclave.example.com",
            ],
            check=True,
            capture_output=True,
        )
        cert_pem = cert_path.read_bytes()
        key_pem = key_path.read_bytes()
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
