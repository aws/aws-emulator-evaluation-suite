"""concurrent-put-then-delete-policy-ordering."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-then-delete-policy-ordering"
GROUP = "concurrency"
SERVICES = ["acm-pca"]


_NO_POLICY_MESSAGE = "Could not find policy for specified resource."
_SUCCEEDED = ("succeeded", None)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DeletePolicy racing a PutPolicy on one CA leaves either the submitted policy intact or
    no policy (ResourceNotFoundException); each racer succeeds or gets the InflightPolicy error,
    and a DeletePolicy that lands before the write is refused with ResourceNotFoundException."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = _sample_policy(ca_arn, account_id)

    pre_code, pre_message = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert pre_code == "ResourceNotFoundException", (
        f"expected no policy on a fresh CA, got GetPolicy code {pre_code!r}"
    )
    assert pre_message == _NO_POLICY_MESSAGE, f"unexpected GetPolicy message {pre_message!r}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        put_future = pool.submit(acmpca.put_policy, ResourceArn=ca_arn, Policy=policy_doc)
        delete_future = pool.submit(acmpca.delete_policy, ResourceArn=ca_arn)
        put_err = _future_outcome(put_future)
        delete_err = _future_outcome(delete_future)

    # A colliding policy write is refused with InvalidPolicyException (InflightPolicy),
    # not ConcurrentModificationException. A DeletePolicy served before PutPolicy commits finds
    # no policy yet and is refused with ResourceNotFoundException.
    inflight = (
        "InvalidPolicyException",
        f"InflightPolicy: There is an existing policy inflight for resource: {ca_arn}",
    )
    no_policy = ("ResourceNotFoundException", _NO_POLICY_MESSAGE)
    assert put_err in (_SUCCEEDED, inflight), f"unexpected PutPolicy outcome: {put_err!r}"
    assert delete_err in (_SUCCEEDED, inflight, no_policy), f"unexpected DeletePolicy outcome: {delete_err!r}"

    final_policy_doc: str | None = None
    final_code: str | None = None
    final_message: str | None = None
    try:
        final_policy_doc = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    except ClientError as e:
        final_code = e.response["Error"]["Code"]
        final_message = e.response["Error"].get("Message")

    # A refused PutPolicy wrote nothing; an accepted PutPolicy whose DeletePolicy found no policy
    # committed after the delete and is still in place.
    if put_err != _SUCCEEDED:
        assert final_policy_doc is None, (
            f"GetPolicy returned a policy although PutPolicy was refused with {put_err!r}"
        )
    elif delete_err == no_policy:
        assert final_policy_doc is not None, (
            f"GetPolicy found no policy although PutPolicy succeeded after DeletePolicy was refused "
            f"with {delete_err!r}: {final_code} {final_message!r}"
        )

    if final_policy_doc is not None:
        landed = json.loads(final_policy_doc)
        submitted = json.loads(policy_doc)
        assert landed["Statement"][0]["Sid"] == submitted["Statement"][0]["Sid"], (
            "GetPolicy returned a policy that does not match what PutPolicy "
            "submitted -- indicates a partially-applied write under the race"
        )
        assert landed["Statement"][0]["Resource"] == ca_arn, (
            f"GetPolicy returned a policy scoped to the wrong resource: "
            f"{landed['Statement'][0]['Resource']!r} != {ca_arn!r}"
        )
        assert set(landed["Statement"][0]["Action"]) == set(submitted["Statement"][0]["Action"]), (
            "GetPolicy returned a truncated/corrupted action list under the race"
        )
    else:
        assert final_code == "ResourceNotFoundException", (
            f"GetPolicy failed with an unexpected code after the race: {final_code}"
        )
        assert final_message == _NO_POLICY_MESSAGE, (
            f"GetPolicy failed with an unexpected message after the race: {final_message!r}"
        )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


def _future_outcome(future) -> tuple[str, str | None]:
    """_SUCCEEDED when the call succeeded (an accepted outcome here), else (code, message)."""
    try:
        future.result()
        return _SUCCEEDED
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")


def _sample_policy(ca_arn: str, account_id: str) -> str:
    # Mirrors AWS's own documented example of a private-CA resource policy:
    # https://docs.aws.amazon.com/privateca/latest/userguide/pca-rbp.html
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealCrossAccountReadOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
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
    )


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    config = {
        "KeyAlgorithm": "RSA_2048",
        "SigningAlgorithm": "SHA256WITHRSA",
        "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
    }
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityConfiguration=config,
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real-check", "Value": "concurrent-put-then-delete-policy-ordering"}],
    )
    ca_arn = resp["CertificateAuthorityArn"]

    def _cleanup() -> None:
        try:
            acmpca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return ca_arn


def _wait_for_ca_status(
    ctx, ca_arn: str, target_statuses: set[str], timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {target_statuses}, last status was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
