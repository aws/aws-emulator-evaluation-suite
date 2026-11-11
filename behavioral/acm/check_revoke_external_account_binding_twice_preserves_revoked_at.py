"""revoke-external-account-binding-twice-preserves-revoked-at."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-external-account-binding-twice-preserves-revoked-at"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second RevokeAcmeExternalAccountBinding on the same binding succeeds (no
    ConflictException) and leaves RevokedAt unchanged from the first revoke."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)
    role_arn = _create_eab_role(ctx, allow_acme=True)

    eab = _retry_create_binding(acm, endpoint_arn, role_arn)["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)))

    before = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert before.get("RevokedAt") is None, "freshly created binding must not be revoked yet"

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    after_first = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert after_first.get("RevokedAt") is not None, "RevokedAt must be set after the first revoke"

    # The redundant revoke succeeds (idempotent, no ConflictException) -- what
    # matters is that RevokedAt is unaffected by the redundant call.
    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    after_second = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert after_second["RevokedAt"] == after_first["RevokedAt"], (
        "RevokedAt must be unchanged by the redundant second revoke call"
    )


def _error_code(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _ignore(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_active_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "ACTIVE", f"ACME endpoint did not become ACTIVE (status={status})"
    return arn


def _create_eab_role(ctx, allow_acme: bool) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-acme-eab-role-")
    if allow_acme:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "acm-acme.amazonaws.com"},
                    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                    "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
                }
            ],
        }
    else:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: iam.delete_role(RoleName=name)))
    return role_arn


def _retry_create_binding(acm, endpoint_arn: str, role_arn: str, timeout_s: float = 45.0, interval_s: float = 3.0) -> dict:
    """CreateAcmeExternalAccountBinding validates RoleArn assumability against IAM, which lags
    create_role by an eventually-consistent propagation window; retry on that specific denial
    rather than sleeping a fixed guess before the call."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding still denied after {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
