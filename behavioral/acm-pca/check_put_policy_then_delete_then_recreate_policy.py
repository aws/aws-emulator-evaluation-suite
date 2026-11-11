"""put-policy-then-delete-then-recreate-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-policy-then-delete-then-recreate-policy"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"
_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeletePolicy removes a policy, PutPolicy can attach a new policy to the
    same CA and GetPolicy reflects only the new document -- no remnant of the old
    statement survives the delete-then-recreate cycle."""
    client = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, arn))
    _activate_root_ca(ctx, arn)

    # Principal must be a real, existing AWS account -- the caller's own account
    # satisfies that trivially. The old/new documents are distinguished by Sid and
    # granted action, not by account, since we only have one real account to use.
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    client.put_policy(ResourceArn=arn, Policy=json.dumps(_simple_policy(arn, account_id, "OldPrincipal", "acm-pca:ListTags")))
    fetched_old = client.get_policy(ResourceArn=arn)["Policy"]
    assert "OldPrincipal" in fetched_old, f"expected Sid OldPrincipal in policy, got {fetched_old!r}"
    assert "acm-pca:ListTags" in fetched_old, f"expected acm-pca:ListTags in policy, got {fetched_old!r}"

    client.delete_policy(ResourceArn=arn)
    code, message = _error(lambda: client.get_policy(ResourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after DeletePolicy, got {code!r}"
    assert message == "Could not find policy for specified resource.", f"unexpected message: {message!r}"

    client.put_policy(ResourceArn=arn, Policy=json.dumps(_simple_policy(arn, account_id, "NewPrincipal", "acm-pca:DescribeCertificateAuthority")))
    fetched_new = client.get_policy(ResourceArn=arn)["Policy"]
    parsed_new = json.loads(fetched_new)
    assert parsed_new["Statement"][0]["Sid"] == "NewPrincipal", f"expected Sid NewPrincipal, got {parsed_new['Statement'][0]['Sid']!r}"
    assert "acm-pca:DescribeCertificateAuthority" in fetched_new, f"expected acm-pca:DescribeCertificateAuthority in recreated policy, got {fetched_new!r}"
    assert "OldPrincipal" not in fetched_new, f"OldPrincipal Sid survived recreate: {fetched_new!r}"
    assert "acm-pca:ListTags" not in fetched_new, f"stale acm-pca:ListTags action survived recreate: {fetched_new!r}"


def _simple_policy(ca_arn: str, account_id: str, sid: str, action: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": [action],
                "Resource": ca_arn,
            }
        ],
    }


def _create_ca(ctx) -> str:
    client = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")
    resp = client.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": _KEY_ALGORITHM,
            "SigningAlgorithm": _SIGNING_ALGORITHM,
            "Subject": {"CommonName": cn[:64]},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    return resp["CertificateAuthorityArn"]


def _wait_for_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    client = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {target_statuses}, last seen {last}")


def _wait_for_certificate(ctx, ca_arn, cert_arn, timeout_s=90.0, interval_s=3.0):
    client = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate never became available, last error: {last_code}")


def _activate_root_ca(ctx, arn) -> None:
    client = ctx.client("acm-pca")
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=90)
    csr = client.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    cert_arn = client.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm=_SIGNING_ALGORITHM,
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 365, "Type": "DAYS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, arn, cert_arn)
    client.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=cert_pem)
    _wait_for_status(ctx, arn, {"ACTIVE"}, timeout_s=90)


def _best_effort_delete(ctx, arn) -> None:
    client = ctx.client("acm-pca")
    try:
        status = client.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        client.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _wait_for_status(ctx, arn, {"DISABLED"}, timeout_s=60)
    client.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
