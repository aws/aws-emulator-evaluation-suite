"""describe-domain-after-delete-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-domain-after-delete-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: a deleted domain must no longer resolve to a pool, a
    second delete on the same (now-dead) id is rejected, and the identifier is reusable."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    domain = ctx.unique_name("sim2real-behav-cip-domain-").lower()
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda _p=pool_id, _d=domain: _safe_delete_domain(c, _d, _p))

    # positive control: the domain really is bound to the pool before we delete it
    before = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert before.get("UserPoolId") == pool_id, (
        f"expected domain bound to pool {pool_id} before delete, got {before}"
    )

    c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    after = c.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
    assert after == {}, f"expected deleted domain to describe as fully empty, got {after}"

    # a mutation on the dead id also fails. Real AWS answers InvalidParameterException here,
    # not ResourceNotFoundException -- a fully-gone domain and a domain that's merely detached
    # from this pool are, from DeleteUserPoolDomain's perspective, the same rejection.
    code, message = _error(lambda: c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException re-deleting a gone domain, got {code!r}"
    )
    expected_message = "No such domain or user pool exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the freed identifier is reusable
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    reused = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert reused.get("UserPoolId") == pool_id, (
        f"expected freed domain name to be reusable, got {reused}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_domain(c, domain, pool_id):
    try:
        c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidParameterException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
