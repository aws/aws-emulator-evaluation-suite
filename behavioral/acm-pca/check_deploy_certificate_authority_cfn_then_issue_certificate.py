"""deploy-certificate-authority-cfn-then-issue-certificate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-certificate-authority-cfn-then-issue-certificate"
GROUP = "deploy"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_LEAF_TEMPLATE_ARN = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CA provisioned by a CloudFormation stack (CA, self-signed certificate, activation)
    reaches ACTIVE and issues a retrievable end-entity certificate, so the deployed
    resource works, not just CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    acmpca = ctx.client("acm-pca")

    common_name = ctx.unique_name("sim2real-behav-")[:64]
    stack_name = ctx.unique_name("sim2real-behav-acmpca-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"CommonName": {"Type": "String"}},
        "Resources": {
            "CA": {
                "Type": "AWS::ACMPCA::CertificateAuthority",
                "Properties": {
                    "Type": "ROOT",
                    "KeyAlgorithm": "RSA_2048",
                    "SigningAlgorithm": "SHA256WITHRSA",
                    "Subject": {"CommonName": {"Ref": "CommonName"}},
                },
            },
            "CACertificate": {
                "Type": "AWS::ACMPCA::Certificate",
                "Properties": {
                    "CertificateAuthorityArn": {"Fn::GetAtt": ["CA", "Arn"]},
                    "CertificateSigningRequest": {
                        "Fn::GetAtt": ["CA", "CertificateSigningRequest"]
                    },
                    "SigningAlgorithm": "SHA256WITHRSA",
                    "TemplateArn": _ROOT_TEMPLATE_ARN,
                    "Validity": {"Type": "YEARS", "Value": 1},
                },
            },
            "CAActivation": {
                "Type": "AWS::ACMPCA::CertificateAuthorityActivation",
                "Properties": {
                    "CertificateAuthorityArn": {"Fn::GetAtt": ["CA", "Arn"]},
                    "Certificate": {"Fn::GetAtt": ["CACertificate", "Certificate"]},
                    "Status": "ACTIVE",
                },
            },
        },
        "Outputs": {
            "CertificateAuthorityArn": {"Value": {"Fn::GetAtt": ["CA", "Arn"]}}
        },
    }

    def _delete_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 400}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": "CommonName", "ParameterValue": common_name}],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )

    ctx.on_cleanup(_delete_stack)

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    ca_arn = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "CertificateAuthorityArn")

    # Disable the CA before the stack delete tears it down: DeleteCertificateAuthority
    # rejects an ACTIVE CA (InvalidStateException), and CloudFormation's resource
    # handler does not disable it for you.
    def _disable_ca(arn: str = ca_arn) -> None:
        try:
            desc = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if desc["CertificateAuthority"]["Status"] == "ACTIVE":
            acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            _poll_until(
                lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)[
                    "CertificateAuthority"
                ]["Status"],
                lambda s: s == "DISABLED",
                timeout_s=60.0,
            )

    ctx.on_cleanup(_disable_ca)

    status = _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"CFN-deployed CA did not reach ACTIVE, got {status!r}"

    leaf_csr_pem = _generate_rsa_csr_pem(f"leaf.{common_name}")
    issued = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=leaf_csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_LEAF_TEMPLATE_ARN,
        Validity={"Type": "DAYS", "Value": 30},
    )
    cert_arn = issued["CertificateArn"]
    assert cert_arn, f"IssueCertificate returned no CertificateArn: {issued!r}"

    certificate_pem = _wait_for_certificate(acmpca, ca_arn, cert_arn)
    assert "-----BEGIN CERTIFICATE-----" in certificate_pem, (
        f"GetCertificate (independent read at the CFN-deployed CA) did not return a PEM "
        f"certificate: {certificate_pem[:120]!r}"
    )
    assert "-----END CERTIFICATE-----" in certificate_pem, (
        f"GetCertificate PEM is missing its END marker: {certificate_pem[:120]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_certificate(acmpca, ca_arn: str, cert_arn: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)[
                "Certificate"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"issued certificate not available within {timeout_s}s")


def _generate_rsa_csr_pem(common_name: str) -> bytes:
    """Generate a PKCS#10 CSR PEM. Prefers the `cryptography` library; falls back to the
    `openssl` CLI if that package is not installed."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .sign(key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM)
    except ImportError:
        pass

    import subprocess
    import tempfile

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = f"{tmp}/key.pem"
        csr_path = f"{tmp}/csr.pem"
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={common_name}",
                "-keyout", key_path, "-out", csr_path,
            ],
            check=True,
            capture_output=True,
        )
        with open(csr_path, "rb") as f:
            return f.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
