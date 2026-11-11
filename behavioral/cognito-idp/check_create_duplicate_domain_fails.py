"""create-duplicate-domain-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-domain-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolDomain with a domain already taken is refused with InvalidParameterException
    "Domain already exists.", the original domain stays ACTIVE on its pool, and a different domain
    on another pool is created."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool(c, _id))
    domain = ctx.unique_name("sim2real-behav-cip-domain-").lower()
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda _p=pool_id, _d=domain: c.delete_user_pool_domain(Domain=_d, UserPoolId=_p))
    # DeleteUserPoolDomain (and, transitively, DeleteUserPool) rejects a domain that hasn't
    # finished provisioning yet, so cleanup silently orphans both unless we wait for ACTIVE here.
    _wait_active(c, domain)

    try:
        c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a duplicate domain, got {code}"
    )
    assert message == "Domain already exists.", (
        f"expected the exact duplicate-domain message, got {message!r}"
    )

    # Effect absent: an independent read (DescribeUserPoolDomain, not the mutating call's own
    # response) shows the rejected duplicate did not repoint or otherwise disturb the domain.
    desc = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert desc["UserPoolId"] == pool_id, (
        f"expected domain {domain!r} still bound to {pool_id!r} after rejected duplicate "
        f"create, got {desc.get('UserPoolId')!r}"
    )
    assert desc["Status"] == "ACTIVE", (
        f"expected domain {domain!r} still ACTIVE after rejected duplicate create, got "
        f"{desc.get('Status')!r}"
    )

    # Positive control: a different domain name on a fresh pool (a pool has at most one domain)
    # succeeds, so the rejection above is specific to the name collision.
    other_pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool2-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=other_pool_id: _delete_pool(c, _id))
    other_domain = ctx.unique_name("sim2real-behav-cip-domain2-").lower()
    c.create_user_pool_domain(Domain=other_domain, UserPoolId=other_pool_id)
    ctx.on_cleanup(lambda _p=other_pool_id, _d=other_domain: c.delete_user_pool_domain(Domain=_d, UserPoolId=_p))
    other_desc = _wait_active(c, other_domain)
    assert other_desc["UserPoolId"] == other_pool_id, (
        f"expected control domain {other_domain!r} bound to {other_pool_id!r}, got "
        f"{other_desc.get('UserPoolId')!r}"
    )


def _wait_active(c, domain: str, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
        if last.get("Status") == "ACTIVE":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain!r} never reached ACTIVE within {timeout_s}s, last: {last!r}")


def _delete_pool(c, pool_id: str) -> None:
    """DeleteUserPool rejects a pool with DeletionProtection=ACTIVE -- deactivate first so
    cleanup can't be silently skipped by ctx.on_cleanup's swallowed exception."""
    try:
        c.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    c.delete_user_pool(UserPoolId=pool_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
