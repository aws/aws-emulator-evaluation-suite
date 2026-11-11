"""create-describe-delete-domain."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-describe-delete-domain"
GROUP = 'user-pool-domain'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolDomain, DescribeUserPoolDomain and DeleteUserPoolDomain form a full cycle."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    domain = ctx.unique_name("sim2real-behav-cip-domain-").lower()
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    domain_deleted = {"done": False}

    def _cleanup_domain():
        if not domain_deleted["done"]:
            c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    ctx.on_cleanup(_cleanup_domain)

    desc = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert desc.get("UserPoolId") == pool_id, (
        f"expected domain bound to pool {pool_id}, got {desc.get('UserPoolId')}"
    )

    c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    domain_deleted["done"] = True

    desc_after = c.describe_user_pool_domain(Domain=domain).get("DomainDescription", {})
    assert desc_after.get("UserPoolId") is None, (
        f"expected no UserPoolId bound after delete, got {desc_after}"
    )

    # the delete must also make the domain unusable, not just unbound in describe:
    # a second delete on the same domain/pool pair is a mutation on the dead id and
    # must fail, not silently succeed as a no-op. Measured on real AWS: the domain is
    # no longer associated with pool_id, so this is InvalidParameterException (the
    # mismatched-association error), not ResourceNotFoundException (reserved for a
    # domain name that never existed at all).
    try:
        c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException deleting an already-deleted domain, got {code}"
    )
    assert message == "No such domain or user pool exists.", (
        f"expected the exact already-deleted-domain message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
