"""concurrent-delete-certificate-authority-race."""
from __future__ import annotations

import threading
import time
from typing import Any

from behavioral_harness import tags


CHECK = "concurrent-delete-certificate-authority-race"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteCertificateAuthority calls on the same CA never both fail, fail only
    with InvalidStateException, and the CA converges to DELETED whether one or both succeed."""
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    ca_arn = _create_ca(ctx)
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})

    results = _race_delete(acmpca, ClientError, ca_arn)

    oks = [k for k, (status, _) in results.items() if status == "ok"]
    errs = [(k, v) for k, (status, v) in results.items() if status == "error"]

    summary = f"a={results.get('a')}, b={results.get('b')}"
    # Both concurrent deletes can land inside the same deletable-state window and both
    # report success (DeleteCertificateAuthority is idempotent at that layer); the one
    # invariant that must hold is that a delete NEVER fails with anything other than
    # InvalidStateException (never a corrupted/ambiguous error), and it never leaves
    # both calls failing (at least one must actually take effect).
    assert len(oks) >= 1, f"expected at least one winner, {summary}"
    for _key, code in errs:
        # message varies: no stable loser message is observable; on AWS both concurrent
        # deletes succeed, so the refusal text cannot be taken from a live call.
        assert code == "InvalidStateException", f"loser saw unexpected error {code}; {summary}"

    final_status = _wait_for_ca_status(ctx, ca_arn, {"DELETED"})
    assert final_status == "DELETED", f"expected CA to converge to DELETED, got {final_status}; {summary}"


def _create_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-pca-")},
        },
        Tags=[{"Key": "sim2real", "Value": "concurrent-delete-certificate-authority-race"}],
    )
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    return ca_arn


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    from botocore.exceptions import ClientError

    acmpca = ctx.client("acm-pca")
    try:
        acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "InvalidStateException"):
            raise


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


def _race_delete(acmpca, client_error_cls, ca_arn: str) -> dict[str, tuple[str, Any]]:
    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def delete_call(key: str) -> None:
        barrier.wait()
        try:
            acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn)
            results[key] = ("ok", None)
        except client_error_cls as e:
            results[key] = ("error", e.response["Error"]["Code"])

    t1 = threading.Thread(target=delete_call, args=("a",))
    t2 = threading.Thread(target=delete_call, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
