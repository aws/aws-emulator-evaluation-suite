"""put-policy-invalid-principal."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-policy-invalid-principal"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")

def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _delete_ca(ctx, ca_arn):
    """Poll-and-retry teardown: DeleteCertificateAuthority raises InvalidStateException while the
    CA is still settling right after creation, so the delete is retried. Raises (rather than
    swallowing) if it still cannot delete."""
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            status = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if status in ("PENDING_DELETION", "DELETED"):
            return
        if status == "CREATING":
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(2)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {ca_arn} within 120s. "
        f"It is STILL BILLING. Delete it manually: DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )

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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutPolicy rejects a principal that is a well-formed but non-existent 12-digit account with
    InvalidPolicyException and attaches nothing (independent GetPolicy read), while the same
    statement naming the caller's own account is accepted, so the refusal is about the principal."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    account = arn.split(":")[4]

    def _policy_for(principal: str) -> str:
        return (
            '{"Version":"2012-10-17","Statement":[{"Sid":"ProbeShare","Effect":"Allow",'
            '"Principal":{"AWS":"' + principal + '"},'
            '"Action":["acm-pca:DescribeCertificateAuthority","acm-pca:GetCertificate"],'
            '"Resource":"' + arn + '"}]}'
        )

    # Break exactly one thing: a syntactically-valid account number that does not
    # correspond to any real AWS account.
    refusal = _err(lambda: pca.put_policy(ResourceArn=arn, Policy=_policy_for("999999999999")))
    assert refusal == ("InvalidPolicyException", "InvalidPolicy: Principal not found."), refusal

    # Effect absent: the rejected call must not have attached anything.
    absent = _err(lambda: pca.get_policy(ResourceArn=arn))
    assert absent == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"a PutPolicy rejected for an invalid principal must not attach a policy anyway, got {absent!r}"
    )

    # Positive control: the identical statement shape using the caller's own real,
    # existing account id is accepted and retrievable.
    pca.put_policy(ResourceArn=arn, Policy=_policy_for(account))
    ctx.on_cleanup(lambda: _best_effort(lambda: pca.delete_policy(ResourceArn=arn)))
    stored = json.loads(pca.get_policy(ResourceArn=arn)["Policy"])
    principal = stored["Statement"][0]["Principal"]["AWS"]
    principal_values = principal if isinstance(principal, list) else [principal]
    assert any(account in value for value in principal_values), (
        f"expected principal to reference account {account!r}, got {principal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
