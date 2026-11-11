"""get-policy-not-found."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-policy-not-found"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success
    raises, so a target accepting the call is reported as an acceptance."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")

def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")

def _delete_ca(ctx, ca_arn):
    try:
        ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_ca(ctx, **overrides):
    """Create a cheap, never-activated ROOT CA (SHORT_LIVED_CERTIFICATE usage mode,
    never issues a cert) and register its teardown. Retries on throttling since
    CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
    }
    body.update(overrides)
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))
    return ca_arn

def _org_sharing_policy(ca_arn, own_account_id):
    # The Organizations-sharing wildcard shape (scoped by PrincipalOrgID /
    # PrincipalAccount conditions) does not name a specific external account, so
    # AWS accepts it without having to validate that some other real account exists.
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realacmpcashare",
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
    })

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPolicy on a CA with no resource policy raises ResourceNotFoundException, while PutPolicy
    then GetPolicy on the same CA returns the attached document, so the failure is about the absent
    policy."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    _poll_until(
        lambda: pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"],
        lambda s: s == "PENDING_CERTIFICATE",
        timeout_s=60,
        description="CA reaching PENDING_CERTIFICATE",
    )

    refusal = _error(lambda: pca.get_policy(ResourceArn=arn))
    assert refusal == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected ResourceNotFoundException, got {refusal!r}"
    )

    # Positive control: the identical CA, still with no certificate imported, really
    # can have a policy attached and read back.
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    pca.put_policy(ResourceArn=arn, Policy=_org_sharing_policy(arn, own_account_id))
    attached = json.loads(pca.get_policy(ResourceArn=arn)["Policy"])
    sid = attached["Statement"][0]["Sid"]
    assert sid == "sim2realacmpcashare", f"expected Sid 'sim2realacmpcashare', got {sid!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
