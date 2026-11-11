"""concurrent-put-policy-delete-policy-race."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

from behavioral_harness import tags


CHECK = "concurrent-put-policy-delete-policy-race"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing PutPolicy and DeletePolicy on one CA fails only with InvalidPolicyException
    (an existing policy inflight), and afterwards the policy is either absent or exactly one of the
    two raced documents, never a partial value."""
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    ca_arn = _create_ca(ctx)
    _activate_root_ca(ctx, ca_arn)

    baseline_policy = _build_policy(ca_arn, "Sim2RealBaseline", own_account_id)
    race_policy = _build_policy(ca_arn, "Sim2RealRaceUpdate", own_account_id)

    def ensure_baseline() -> None:
        acmpca.put_policy(ResourceArn=ca_arn, Policy=baseline_policy)

    ensure_baseline()
    current = json.loads(acmpca.get_policy(ResourceArn=ca_arn)["Policy"])
    assert current["Statement"][0]["Sid"] == "Sim2RealBaseline"

    ctx.on_cleanup(lambda: _ignore_not_found(ClientError, lambda: acmpca.delete_policy(ResourceArn=ca_arn)))

    results = _race_put_delete(acmpca, ClientError, ca_arn, race_policy)
    oks = [k for k, (status, _) in results.items() if status == "ok"]
    errs = [(k, v) for k, (status, v) in results.items() if status == "error"]
    summary = f"put={results.get('put')}, delete={results.get('delete')}"

    # AWS does not appear to serialize PutPolicy/DeletePolicy with a hard optimistic
    # lock that always produces exactly one loser -- both racers can report success
    # (whichever write lands last on the backend simply wins). The invariant that must
    # hold regardless of the race outcome: no error code other than the
    # InvalidPolicyException("InflightPolicy: ...") that ACM PCA raises when a second
    # policy write collides with one already in flight, at least one call succeeds,
    # and the final policy state is one of the two complete, well-formed documents (or
    # fully absent) -- never a corrupted hybrid.
    assert len(oks) >= 1, f"expected at least one winner, {summary}"
    inflight_message = f"InflightPolicy: There is an existing policy inflight for resource: {ca_arn}"
    for _key, (code, message) in errs:
        assert code == "InvalidPolicyException", f"loser saw unexpected error {code}; {summary}"
        assert message == inflight_message, f"loser saw unexpected message {message!r}; {summary}"


    try:
        final_raw = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    except ClientError as e:
        code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"unexpected GetPolicy error {code}; {summary}"
        assert message == "Could not find policy for specified resource.", (
            f"unexpected GetPolicy message {message!r}; {summary}"
        )
    else:
        final_policy = json.loads(final_raw)
        sid = final_policy["Statement"][0]["Sid"]
        assert sid in ("Sim2RealBaseline", "Sim2RealRaceUpdate"), f"corrupted policy sid={sid!r}; {summary}"


def _create_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-pca-")},
        },
        Tags=[{"Key": "sim2real", "Value": "concurrent-put-policy-delete-policy-race"}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    return ca_arn


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    """Delete the CA, disabling it first: ACM PCA refuses to delete an ACTIVE CA."""
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    try:
        status = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "DELETED":
        return
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _wait_for_ca_status(ctx, ca_arn, {"DISABLED"})
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn)


def _wait_for_ca_status(ctx, ca_arn: str, target_statuses: set, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {target_statuses}, last status={last}")


def _poll_get_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "RequestInProgressException":
                raise
        time.sleep(interval_s)
    raise AssertionError("certificate never became available within timeout")


def _activate_root_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    csr = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )
    cert_arn = issue_resp["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, ca_arn, cert_arn)
    acmpca.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=cert_pem)
    _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"})


def _build_policy(ca_arn: str, sid: str, own_account_id: str) -> str:
    # AWS Private CA validates that an AWS-account Principal actually exists, so a
    # synthetic 12-digit account id (e.g. "123456789012") is rejected with
    # InvalidPolicyException ("Principal not found"). Use the documented
    # Organizations-sharing shape (wildcard Principal scoped by PrincipalOrgID /
    # PrincipalAccount conditions) instead, which does not require a real external
    # account.
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
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


def _race_put_delete(acmpca, client_error_cls, ca_arn: str, race_policy: str) -> dict[str, tuple[str, Any]]:
    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def put_call() -> None:
        barrier.wait()
        try:
            acmpca.put_policy(ResourceArn=ca_arn, Policy=race_policy)
            results["put"] = ("ok", None)
        except client_error_cls as e:
            results["put"] = ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    def delete_call() -> None:
        barrier.wait()
        try:
            acmpca.delete_policy(ResourceArn=ca_arn)
            results["delete"] = ("ok", None)
        except client_error_cls as e:
            results["delete"] = ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    t1 = threading.Thread(target=put_call)
    t2 = threading.Thread(target=delete_call)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return results


def _ignore_not_found(client_error_cls, fn) -> None:
    try:
        fn()
    except client_error_cls as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidStateException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
