"""concurrent-set-identity-pool-roles-last-writer-consistent."""
from __future__ import annotations

import concurrent.futures
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-set-identity-pool-roles-last-writer-consistent"
GROUP = 'concurrency'
SERVICES = ['cognito-identity']

def _cognito_trust_policy(pool_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
            }
        ],
    }

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _role_arn(iam_client, ctx, pool_id, slot="auth"):
    """Create a real IAM role Cognito Identity can pass; register delete cleanup; return its ARN."""
    role_name = f"sim2real-behav-role-{slot}-{uuid.uuid4().hex[:8]}"[:60]
    arn = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_cognito_trust_policy(pool_id)),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_role(RoleName=role_name))
    return arn

def _set_roles(client, pool_id, roles, timeout_s=60, **kwargs):
    """SetIdentityPoolRoles with bounded retry for IAM role propagation delay (transient codes only)."""
    transient = {
        "AccessDeniedException",
        "InvalidParameterException",
        "ThrottlingException",
        "TooManyRequestsException",
        "ConcurrentModificationException",
    }
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles, **kwargs)
        except Exception as exc:  # noqa: BLE001 - propagation races
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code not in transient or time.monotonic() >= deadline:
                raise
            time.sleep(3)

def _run_concurrent(fns):
    """Run callables in parallel; return results 1:1 in submission order (exceptions captured, not raised)."""
    results = [None] * len(fns)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns))) as ex:
        fut_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                results[i] = exc
    return results

def _error_codes(results):
    """Error codes for run_concurrent entries that raised (ClientError -> Error.Code, else class name)."""
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent SetIdentityPoolRoles calls race safely: final state matches exactly one of the writers."""
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    unauth_arn = _role_arn(iam, ctx, pool_id, "unauth")
    candidate_arns = [_role_arn(iam, ctx, pool_id, "auth"), _role_arn(iam, ctx, pool_id, "authalt")]
    # Prime with a valid config so IAM role propagation completes before racing; the primed
    # authenticated role is none of the racers', so the final read must show a racer's write.
    prime_arn = _role_arn(iam, ctx, pool_id, "authprime")
    _set_roles(ev, pool_id, {"unauthenticated": unauth_arn, "authenticated": prime_arn})

    fns = []
    for arn in candidate_arns:
        for _ in range(3):
            fns.append(
                lambda arn=arn: ev.set_identity_pool_roles(
                    IdentityPoolId=pool_id,
                    Roles={"unauthenticated": unauth_arn, "authenticated": arn},
                )
            )
    results = _run_concurrent(fns)

    n_success = sum(1 for r in results if not isinstance(r, BaseException))
    assert n_success >= 1, "at least one concurrent SetIdentityPoolRoles writer must win the race"

    # Losers must be rejected with a structured concurrency/throttling error --
    # never a semantic rejection (which would mean the request was misinterpreted)
    # and never an unhandled server fault.
    codes = _error_codes(results)
    for code in codes:
        assert code, f"a losing racer failed without an API error code: {codes}"
        assert code not in ("ValidationException", "AccessDeniedException", "ResourceNotFoundException"), (
            f"losing racer got a semantic error {code} instead of a concurrency error: {codes}"
        )

    final = ev.get_identity_pool_roles(IdentityPoolId=pool_id)
    final_role = final["Roles"]["authenticated"]
    assert final_role in candidate_arns, (
        f"final authenticated role {final_role!r} must be exactly one of the racing writers' values, "
        "not a corrupted/merged value"
    )
    assert final["Roles"]["unauthenticated"] == unauth_arn, (
        "unauthenticated role must survive the race intact"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
