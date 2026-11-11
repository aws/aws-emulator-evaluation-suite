"""deploy-cloudformation-ca-issues-certificate."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "deploy-cloudformation-ca-issues-certificate"
GROUP = "deploy"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A root CA created, self-signed, and activated by a CloudFormation stack is ACTIVE and
    issues a leaf certificate that GetCertificate returns as PEM."""
    require_tools("openssl")
    cfn = ctx.client("cloudformation")
    acmpca = ctx.client("acm-pca")

    stack_name = ctx.unique_name("sim2real-acmpca-cfn-")
    ca_name = ctx.unique_name("sim2real-acmpca-cfn-ca-")[:64]
    template = _build_template(ca_name)

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template), Capabilities=[])
    ctx.on_cleanup(lambda: _safe_delete_stack(ctx, stack_name))

    status = _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in _describe_stack(ctx, stack_name).get("Outputs", [])}
    ca_arn = outputs["CaArn"]
    ca_status = _status(ctx, ca_arn)
    assert ca_status == "ACTIVE", f"CFN-deployed CA is not ACTIVE, got {ca_status}"

    leaf_csr = _generate_leaf_csr(ctx.unique_name("sim2real-acmpca-leaf-")[:64])
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=leaf_csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/EndEntityCertificate/V1",
        Validity={"Value": 30, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_until(
        lambda: _try_get_certificate(ctx, ca_arn, cert_arn), lambda v: v is not None, timeout_s=60
    )
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----"), f"leaf cert PEM missing BEGIN marker: {cert_pem!r}"
    assert cert_pem.rstrip().endswith("-----END CERTIFICATE-----"), f"leaf cert PEM missing END marker: {cert_pem!r}"


def _build_template(ca_name: str) -> dict:
    return {
        "Resources": {
            "Ca": {
                "Type": "AWS::ACMPCA::CertificateAuthority",
                "Properties": {
                    "Type": "ROOT",
                    "KeyAlgorithm": "RSA_2048",
                    "SigningAlgorithm": "SHA256WITHRSA",
                    "Subject": {"CommonName": ca_name},
                },
            },
            "CaCert": {
                "Type": "AWS::ACMPCA::Certificate",
                "Properties": {
                    "CertificateAuthorityArn": {"Ref": "Ca"},
                    "CertificateSigningRequest": {"Fn::GetAtt": ["Ca", "CertificateSigningRequest"]},
                    "SigningAlgorithm": "SHA256WITHRSA",
                    "TemplateArn": "arn:aws:acm-pca:::template/RootCACertificate/V1",
                    "Validity": {"Type": "DAYS", "Value": 3650},
                },
            },
            "CaActivation": {
                "Type": "AWS::ACMPCA::CertificateAuthorityActivation",
                "Properties": {
                    "CertificateAuthorityArn": {"Ref": "Ca"},
                    "Certificate": {"Fn::GetAtt": ["CaCert", "Certificate"]},
                    "Status": "ACTIVE",
                },
            },
        },
        "Outputs": {"CaArn": {"Value": {"Ref": "Ca"}}},
    }


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _describe_stack(ctx, stack_name: str) -> dict:
    cfn = ctx.client("cloudformation")
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]


def _stack_status(ctx, stack_name: str) -> str:
    return _describe_stack(ctx, stack_name)["StackStatus"]


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _try_get_certificate(ctx, ca_arn: str, cert_arn: str):
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "RequestInProgressException":
            return None
        raise


def _generate_leaf_csr(common_name: str) -> bytes:
    """A PKCS#10 CSR with a fresh keypair from the openssl CLI, avoiding a second billed CA."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        key_path = f"{d}/key.pem"
        csr_path = f"{d}/req.csr"
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", csr_path, "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        with open(csr_path, "rb") as f:
            return f.read()


def _safe_delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    if _stack_status_or_gone(ctx, stack_name) == "GONE":
        return
    # Disable the CA first (if it exists and is ACTIVE) so that stack
    # deletion of the AWS::ACMPCA::CertificateAuthority resource does
    # not race with an in-progress state transition.
    # The physical id exists before the stack's Outputs do, so a half-created stack still names its CA.
    try:
        resources = cfn.describe_stack_resources(StackName=stack_name, LogicalResourceId="Ca")["StackResources"]
    except ClientError as exc:
        # A stack that failed before creating its CA has no "Ca" resource to name.
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        resources = []
    ca_arn = resources[0].get("PhysicalResourceId") if resources else None
    if ca_arn:
        ca_status = _status_or_gone(ctx, ca_arn)
        if ca_status == "ACTIVE":
            ctx.client("acm-pca").update_certificate_authority(
                CertificateAuthorityArn=ca_arn, Status="DISABLED"
            )
            _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    cfn.delete_stack(StackName=stack_name)
    final_status = _poll_until(
        lambda: _stack_status_or_gone(ctx, stack_name),
        lambda s: s in ("DELETE_COMPLETE", "GONE", "DELETE_FAILED"),
        timeout_s=300,
        interval_s=2,
    )
    assert final_status != "DELETE_FAILED", f"stack {stack_name} teardown ended in DELETE_FAILED"
    if ca_arn:
        _poll_until(lambda: _status_or_gone(ctx, ca_arn), lambda s: s in ("DELETED", "GONE"), timeout_s=300)


def _status_or_gone(ctx, ca_arn: str) -> str:
    from botocore.exceptions import ClientError

    try:
        return _status(ctx, ca_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return "GONE"


def _stack_status_or_gone(ctx, stack_name: str) -> str:
    from botocore.exceptions import ClientError

    try:
        return _stack_status(ctx, stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":  # "Stack ... does not exist"
            raise
        return "GONE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
