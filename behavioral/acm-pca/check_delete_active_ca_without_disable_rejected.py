"""delete-active-ca-without-disable-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-active-ca-without-disable-rejected"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCertificateAuthority on an ACTIVE private CA is rejected with InvalidStateException and
    leaves the CA untouched; the same delete succeeds once the CA is DISABLED."""
    acmpca = ctx.client("acm-pca")
    common_name = ctx.unique_name("sim2real-behav-")[:64]

    created = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        CertificateAuthorityType="ROOT",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ca_arn = created["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _best_effort_teardown(acmpca, ca_arn))

    _activate_root_ca(acmpca, ca_arn, common_name)
    status = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
        "CertificateAuthority"
    ]["Status"]
    assert status == "ACTIVE", f"CA did not reach ACTIVE after activation; got {status!r}"

    # Negative: deleting an ACTIVE CA directly is rejected.
    refusal = _error_code(lambda: acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn))
    assert refusal == ("InvalidStateException", "The certificate authority is not in a valid state for deletion."), (
        f"expected InvalidStateException with AWS's exact message deleting an ACTIVE CA, "
        f"got {refusal!r}"
    )

    # Effect absent: the CA is still there, still ACTIVE, not deleted.
    still_there = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
        "CertificateAuthority"
    ]
    assert still_there["Status"] == "ACTIVE", (
        f"CA status changed after the rejected delete; expected ACTIVE, "
        f"got {still_there['Status']!r}"
    )

    # Positive control: disable first, then delete succeeds and transitions to DELETED.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "DISABLED",
        timeout_s=60.0,
    )
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn)
    final_status = _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "DELETED",
        timeout_s=60.0,
    )
    assert final_status == "DELETED", (
        f"CA did not reach DELETED after disable+delete; got {final_status!r}"
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


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) on a ClientError. An unexpected
    success raises, so a target accepting a call AWS refuses is reported as an acceptance."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected DeleteCertificateAuthority to be rejected while the CA is ACTIVE, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _best_effort_teardown(acmpca, ca_arn: str) -> None:
    """Ordered, retrying, LOUD teardown: wait out of CREATING, disable if ACTIVE, then delete.
    DeleteCertificateAuthority accepts only CREATING (once settled), PENDING_CERTIFICATE,
    DISABLED or FAILED -- an ACTIVE CA must be disabled first, and a delete issued while the CA
    is still settling is refused with InvalidStateException. A teardown that fires one delete
    and swallows the exception leaks a metered private CA (a few hundred dollars a month)
    indefinitely, so this one retries within a bounded budget and RAISES if it still cannot
    delete, reporting the leak instead of hiding it.
    """
    deadline = time.monotonic() + 45.0
    status = None
    while time.monotonic() < deadline:
        try:
            status = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
                "CertificateAuthority"
            ]["Status"]
        except ClientError:
            return  # no longer addressable; nothing left to clean up
        if status == "DELETED":
            return
        if status == "CREATING":
            time.sleep(2.0)
            continue
        if status == "ACTIVE":
            try:
                acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            except ClientError:
                pass
            time.sleep(2.0)
            continue
        try:
            acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(2.0)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {ca_arn} within 45s "
        f"(last observed Status={status!r}); it is still billing"
    )


def _activate_root_ca(acmpca, ca_arn: str, common_name: str) -> None:
    """Drive a freshly created ROOT CA from PENDING_CERTIFICATE to ACTIVE by generating its
    CSR, self-signing it with the RootCACertificate/V1 template, and importing the result --
    the same state transition CloudFormation's CertificateAuthorityActivation resource
    performs."""
    csr_pem = _wait_for_csr(acmpca, ca_arn)
    issued = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Type": "YEARS", "Value": 1},
    )
    ca_cert_arn = issued["CertificateArn"]
    ca_cert_pem = _wait_for_certificate(acmpca, ca_arn, ca_cert_arn)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("utf-8")
    )
    _poll_until(
        lambda: acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=90.0,
    )


def _wait_for_csr(acmpca, ca_arn: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"CA CSR not available within {timeout_s}s")


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
    raise AssertionError(f"certificate not available within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
