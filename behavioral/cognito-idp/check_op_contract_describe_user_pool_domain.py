"""op-contract-describe-user-pool-domain."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-user-pool-domain"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeUserPoolDomain returns the domain's status; an unknown domain returns an
    EMPTY DomainDescription rather than raising (this is a real, easy-to-miss quirk)."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2real-behav-domain-").lower().replace("_", "-")
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    # Tolerate an already-gone domain: deleting the pool can take the domain with it, and a
    # teardown that raises ResourceNotFoundException would mask the check's real result.
    ctx.on_cleanup(lambda: _safe_delete_domain(idp, domain, pool_id))

    desc = idp.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert desc.get("Domain") == domain, f"expected Domain={domain!r}, got {desc.get('Domain')!r}"
    assert desc.get("UserPoolId") == pool_id, (
        f"expected UserPoolId={pool_id!r}, got {desc.get('UserPoolId')!r}"
    )
    assert desc.get("Status") in {"CREATING", "ACTIVE", "UPDATING"}, (
        f"expected Status in CREATING/ACTIVE/UPDATING, got {desc.get('Status')!r}"
    )

    # Boundary: real AWS does NOT raise ResourceNotFoundException for an unknown domain;
    # it returns 200 with an empty DomainDescription object.
    unknown = idp.describe_user_pool_domain(Domain=domain + "-does-not-exist")["DomainDescription"]
    assert unknown == {} or "Domain" not in unknown, f"expected empty DomainDescription, got {unknown}"


def _safe_delete_domain(idp, domain: str, pool_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
