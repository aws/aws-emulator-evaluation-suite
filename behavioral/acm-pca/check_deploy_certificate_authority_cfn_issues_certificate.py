"""deploy-certificate-authority-cfn-issues-certificate."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-certificate-authority-cfn-issues-certificate"
GROUP = "deploy"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"

_CFN_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  CaCommonName:
    Type: String
Resources:
  Ca:
    Type: AWS::ACMPCA::CertificateAuthority
    Properties:
      Type: ROOT
      KeyAlgorithm: RSA_2048
      SigningAlgorithm: SHA256WITHRSA
      Subject:
        CommonName: !Ref CaCommonName
Outputs:
  CaArn:
    Value: !Ref Ca
""".strip()


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CA deployed via CloudFormation bootstraps (CSR, self-signed root import) and then
    issues and returns an end-entity certificate."""
    require_tools("openssl")

    cfn = ctx.client("cloudformation")
    acmpca = ctx.client("acm-pca")

    stack_name = ctx.unique_name("sim2real-pca-cfn-")
    common_name = ctx.unique_name("sim2real-pca-")[:60]

    ca_arn_box: list[str] = []

    def _cleanup() -> None:
        if ca_arn_box:
            ca_arn = ca_arn_box[0]
            try:
                status = acmpca.describe_certificate_authority(
                    CertificateAuthorityArn=ca_arn
                )["CertificateAuthority"]["Status"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                status = None
            if status == "ACTIVE":
                acmpca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
                _poll_until(
                    lambda: acmpca.describe_certificate_authority(
                        CertificateAuthorityArn=ca_arn
                    )["CertificateAuthority"]["Status"],
                    lambda s: s == "DISABLED",
                    timeout_s=90,
                    desc="CA DISABLED before stack teardown",
                )
        cfn.delete_stack(StackName=stack_name)
        _wait_for_stack_gone(cfn, stack_name, timeout_s=300)

    ctx.on_cleanup(_cleanup)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_CFN_TEMPLATE,
        Parameters=[{"ParameterKey": "CaCommonName", "ParameterValue": common_name}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    stack = _wait_for_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=300)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    ca_arn = outputs["CaArn"]
    ca_arn_box.append(ca_arn)

    # CA reaches PENDING_CERTIFICATE once its key pair/CSR are ready.
    status = _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s in ("PENDING_CERTIFICATE", "FAILED"),
        timeout_s=120,
        desc="CA to reach PENDING_CERTIFICATE",
    )
    assert status == "PENDING_CERTIFICATE", f"CA entered unexpected state {status}"

    ca_csr_pem = _poll_until(
        lambda: _try_get_csr(acmpca, ca_arn),
        lambda v: v is not None,
        timeout_s=60,
        desc="CA CSR to become available",
    )
    assert "BEGIN CERTIFICATE REQUEST" in ca_csr_pem, (
        f"expected a PEM CSR from GetCertificateAuthorityCSR, got: {ca_csr_pem!r}"
    )

    root_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=ca_csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]

    root_cert_pem = _poll_until(
        lambda: _try_get_certificate(acmpca, ca_arn, root_cert_arn),
        lambda v: v is not None,
        timeout_s=90,
        desc="root certificate issuance to complete",
    )["Certificate"]
    assert "BEGIN CERTIFICATE" in root_cert_pem, (
        f"expected a PEM root certificate from GetCertificate, got: {root_cert_pem!r}"
    )

    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=root_cert_pem
    )

    status = _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=90,
        desc="CA to become ACTIVE after import",
    )
    assert status == "ACTIVE", f"CA did not activate after importing root cert: {status}"

    ee_csr_pem = _generate_csr_pem(common_name + "-ee")
    ee_cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=ee_csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )["CertificateArn"]

    ee_result = _poll_until(
        lambda: _try_get_certificate(acmpca, ca_arn, ee_cert_arn),
        lambda v: v is not None,
        timeout_s=90,
        desc="end-entity certificate issuance to complete",
    )
    ee_cert_pem = ee_result["Certificate"]
    ee_chain_pem = ee_result.get("CertificateChain", "")
    assert "BEGIN CERTIFICATE" in ee_cert_pem, (
        f"expected a PEM end-entity certificate from GetCertificate, got: {ee_cert_pem!r}"
    )
    assert ee_cert_pem != root_cert_pem, (
        "end-entity certificate must not be byte-identical to the root CA certificate"
    )
    assert "BEGIN CERTIFICATE" in ee_chain_pem, (
        f"expected a non-empty PEM CertificateChain for the end-entity cert, got: {ee_chain_pem!r}"
    )


def _generate_csr_pem(common_name: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        csr_path = os.path.join(d, "req.csr")
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", csr_path, "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        with open(csr_path) as f:
            return f.read()


def _try_get_csr(acmpca, ca_arn: str) -> str | None:
    try:
        return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    except Exception as e:  # RequestInProgressException while CSR is generated
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        if code == "RequestInProgressException":
            return None
        raise


def _try_get_certificate(acmpca, ca_arn: str, cert_arn: str) -> dict[str, Any] | None:
    try:
        return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
    except Exception as e:  # RequestInProgressException while issuance completes
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        if code == "RequestInProgressException":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last observed: {last!r}")


def _wait_for_stack_status(cfn, stack_name: str, target_statuses: set[str], timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status in target_statuses:
            return stacks[0]
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {status}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s")


def _wait_for_stack_gone(cfn, stack_name: str, timeout_s=300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
            status = stacks[0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status.endswith("FAILED"):
                raise AssertionError(f"stack {stack_name} failed to delete: {status}")
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code == "ValidationError":
                return  # stack no longer exists
            raise
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not finish deleting within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
