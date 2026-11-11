"""deploy-certificate-with-tags-via-cloudformation-tags-queryable."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-certificate-with-tags-via-cloudformation-tags-queryable"
GROUP = "deploy"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags from a CloudFormation certificate's Tags property are listed by ListTagsForCertificate,
    and deleting the stack makes DescribeCertificate fail with ResourceNotFoundException.
    """
    acm = ctx.client("acm")
    cfn = ctx.client("cloudformation")

    # The stack's create handler waits for ISSUED; a private CA issues synchronously, while a
    # DNS-validated domain we do not control would never validate and hang the stack.
    ca_arn = _create_active_private_ca(ctx)

    domain_name = f"{uuid.uuid4().hex[:12]}.sim2real.internal"
    tag_value = f"sim2real-{uuid.uuid4().hex[:8]}"
    stack_name = ctx.unique_name("sim2real-acm-certtags-")
    template = json.dumps(
        {
            "Resources": {
                "Cert": {
                    "Type": "AWS::CertificateManager::Certificate",
                    "Properties": {
                        "DomainName": domain_name,
                        "CertificateAuthorityArn": ca_arn,
                        "Tags": [{"Key": "sim2real-owner", "Value": tag_value}],
                    },
                }
            },
            "Outputs": {"CertArn": {"Value": {"Ref": "Cert"}}},
        }
    )
    deleted = [False]
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: None if deleted[0] else cfn.delete_stack(StackName=stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    cert_arn = outputs["CertArn"]

    desc = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert desc["DomainName"] == domain_name, (
        f"expected DomainName={domain_name!r} on the CFN-issued certificate, got {desc['DomainName']!r}"
    )

    cert_tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]}
    assert cert_tags.get("sim2real-owner") == tag_value, (
        f"expected template Tags property to produce sim2real-owner={tag_value!r} on the live "
        f"certificate via ListTagsForCertificate, got {cert_tags!r}"
    )

    # Delete through the stack, then confirm removal through the *data plane*, not the stack
    # status: a faked DeleteCertificate would leave the certificate describable.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    deleted[0] = True

    expected_message = f"Could not find certificate {cert_arn}."
    code, message = _error_code(lambda: acm.describe_certificate(CertificateArn=cert_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the certificate {cert_arn} after stack deletion, "
        f"got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _create_active_private_ca(ctx) -> str:
    pca = ctx.client("acm-pca")
    resp = pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acm-ca-")},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ca_arn = resp["CertificateAuthorityArn"]

    def _cleanup_ca():
        try:
            pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)

    ctx.on_cleanup(_cleanup_ca)

    _poll_until(
        lambda: pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"][
            "Status"
        ],
        lambda s: s == "PENDING_CERTIFICATE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    issued = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 5, "Type": "YEARS"},
    )
    cert_arn = issued["CertificateArn"]

    def _get_ca_cert():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    cert_pem = _poll_until(_get_ca_cert, lambda c: c is not None, timeout_s=90.0, interval_s=3.0)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _poll_until(
        lambda: pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"][
            "Status"
        ],
        lambda s: s == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return ca_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
