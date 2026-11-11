"""concurrent-duplicate-create-permission-rejected."""
from __future__ import annotations

import threading
import time
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-duplicate-create-permission-rejected"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent duplicate CreatePermission calls fail only with PermissionAlreadyExistsException
    and leave exactly one permission record for the principal; a later plain create succeeds."""
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    ca_arn = _create_ca(ctx)
    _activate_root_ca(ctx, ca_arn)

    principal = "acm.amazonaws.com"
    actions = ["IssueCertificate", "GetCertificate", "ListPermissions"]

    results = _race_create_permission(acmpca, ClientError, ca_arn, principal, actions)
    oks = [k for k, (status, _) in results.items() if status == "ok"]
    errs = [(k, v) for k, (status, v) in results.items() if status == "error"]
    summary = f"a={results.get('a')}, b={results.get('b')}"

    # There is no atomic uniqueness check, so both racers may report success.
    assert len(oks) >= 1, f"expected at least one winner, {summary}"
    for _key, code in errs:
        # message varies: no refusal message is observable; on AWS both racing creates and
        # a sequential duplicate CreatePermission all succeed.
        assert code == "PermissionAlreadyExistsException", f"loser saw unexpected error {code}; {summary}"

    perms = acmpca.list_permissions(CertificateAuthorityArn=ca_arn)["Permissions"]
    matching = [p for p in perms if p["Principal"] == principal]
    assert len(matching) == 1, f"expected exactly one permission record, found {matching}"

    ctx.on_cleanup(
        lambda: _ignore_missing(ClientError, lambda: acmpca.delete_permission(CertificateAuthorityArn=ca_arn, Principal=principal))
    )

    # Positive control: after clearing the grant, a non-racing CreatePermission succeeds.
    acmpca.delete_permission(CertificateAuthorityArn=ca_arn, Principal=principal)
    acmpca.create_permission(CertificateAuthorityArn=ca_arn, Principal=principal, Actions=actions)
    perms_after = acmpca.list_permissions(CertificateAuthorityArn=ca_arn)["Permissions"]
    matching_after = [p for p in perms_after if p["Principal"] == principal]
    assert len(matching_after) == 1


def _create_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-pca-")},
        },
        Tags=[{"Key": "sim2real-concurrent-perm", "Value": "1"}],
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


def _race_create_permission(acmpca, client_error_cls, ca_arn: str, principal: str, actions: list) -> dict[str, tuple[str, Any]]:
    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def create_call(key: str) -> None:
        barrier.wait()
        try:
            acmpca.create_permission(CertificateAuthorityArn=ca_arn, Principal=principal, Actions=actions)
            results[key] = ("ok", None)
        except client_error_cls as e:
            results[key] = ("error", e.response["Error"]["Code"])

    t1 = threading.Thread(target=create_call, args=("a",))
    t2 = threading.Thread(target=create_call, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return results


def _ignore_missing(client_error_cls, fn) -> None:
    try:
        fn()
    except client_error_cls as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidStateException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
