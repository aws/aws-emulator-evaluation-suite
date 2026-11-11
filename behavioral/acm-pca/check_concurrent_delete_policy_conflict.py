"""concurrent-delete-policy-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "concurrent-delete-policy-conflict"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


_NO_POLICY_MESSAGE = "Could not find policy for specified resource."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two overlapping DeletePolicy calls on the same CA both succeed (DeletePolicy is a
    documented no-op without a policy) and the policy is removed; a later PutPolicy and
    DeletePolicy pair still succeeds."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)

    principal_account = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = json.dumps(_build_policy(ca_arn, principal_account))
    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_doc)

    # confirm the policy actually landed before racing its deletion -- otherwise a
    # PutPolicy that silently no-ops would make the post-race ResourceNotFoundException
    # assertions below pass for the wrong reason (never existed, not deleted).
    landed = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert _policy_matches(landed, policy_doc), (
        f"policy did not land before the race: expected {policy_doc!r}, got {landed!r}"
    )

    barrier = threading.Barrier(2)

    def _racer():
        barrier.wait()
        try:
            acmpca.delete_policy(ResourceArn=ca_arn)
            return ("ok", None)
        except Exception as err:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return ("error", err.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _racer(), range(2)))

    oks = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]

    # empirically: DeletePolicy is idempotent, so both concurrent calls
    # succeed -- if either fails, it must be with a real, specific error
    # code, never a bare crash.
    assert len(oks) == 2, f"expected both racing DeletePolicy calls to succeed, got oks={oks} errors={errors}"
    assert len(errors) == 0, f"expected no racer to error, got errors={errors} (oks={oks})"

    # the policy was removed exactly once -- no policy remains attached.
    race_code, race_message = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert race_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after both racers deleted the policy, got {race_code!r}"
    )
    assert race_message == _NO_POLICY_MESSAGE, f"unexpected GetPolicy message: {race_message!r}"

    # positive control: a fresh, non-racing PutPolicy/DeletePolicy pair works cleanly.
    acmpca.put_policy(ResourceArn=ca_arn, Policy=policy_doc)
    control_landed = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert _policy_matches(control_landed, policy_doc), (
        f"control PutPolicy did not land: expected {policy_doc!r}, got {control_landed!r}"
    )
    acmpca.delete_policy(ResourceArn=ca_arn)
    control_code, control_message = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after control DeletePolicy, got {control_code!r}"
    )
    assert control_message == _NO_POLICY_MESSAGE, (
        f"unexpected GetPolicy message: {control_message!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


def _policy_matches(actual_doc_str: str, expected_doc_str: str) -> bool:
    """Compare policy documents on their semantic content, not exact byte
    equality -- AWS Private CA normalizes the Principal (e.g. to an ARN)
    when it echoes a policy back via GetPolicy."""
    a = json.loads(actual_doc_str)["Statement"][0]
    e = json.loads(expected_doc_str)["Statement"][0]
    return (
        a.get("Sid") == e.get("Sid")
        and a.get("Effect") == e.get("Effect")
        and set(a.get("Action", [])) == set(e.get("Action", []))
        and a.get("Resource") == e.get("Resource")
    )


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _build_policy(ca_arn: str, principal_account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realShareReadOnly",
                "Effect": "Allow",
                "Principal": {"AWS": principal_account},
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


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
    )
    return resp["CertificateAuthorityArn"]


def _activate_root_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    def _get_csr():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    csr = _poll_until(_get_csr, lambda v: v is not None, timeout_s=60)
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]

    def _get_cert():
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    cert_pem = _poll_until(_get_cert, lambda v: v is not None, timeout_s=60)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "ACTIVE", timeout_s=60)


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        status = _status(ctx, ca_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    if status != "DELETED":
        acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
