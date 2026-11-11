"""op-contract-delete-user-pool-domain."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-user-pool-domain"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolDomain detaches the domain (DescribeUserPoolDomain then reports it
    unassociated) and rejects deleting a domain from a pool it isn't attached to."""
    idp = ctx.client("cognito-idp")
    pool_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags=pool_tags,
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    other_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool2-"),
        UserPoolTags=pool_tags,
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=other_pool_id))

    domain = _domain_name(ctx)
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: _safe_delete_domain(idp, domain, pool_id))

    # confirm the domain is really attached before we delete it
    before = idp.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert before.get("UserPoolId") == pool_id, "domain should be attached to the pool right after creation"

    # distinct error boundary: deleting a domain from a pool it was never attached to
    # is rejected, not silently accepted as a no-op. This must be checked while the
    # domain is still live and attached to `pool_id` - checking it after the domain has
    # already been deleted would just be re-testing "domain doesn't exist at all",
    # not "domain isn't attached to this pool".
    # Real AWS rejects the mismatched-owner case with InvalidParameterException (the
    # domain exists, it's just not associated with the given pool), not
    # ResourceNotFoundException (which is reserved for a domain that doesn't exist at all).
    code, message = _error(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=other_pool_id))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "The domain is not configured for this user pool.", (
        f"cross-pool DeleteUserPoolDomain: message {message!r}"
    )

    # the rejected cross-pool delete must have had no effect: the domain is still
    # attached to the pool that actually owns it
    mid = idp.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert mid.get("UserPoolId") == pool_id, (
        f"rejected cross-pool delete should not detach the domain, got {mid!r}"
    )

    # success path: delete succeeds, and the domain is truly detached afterwards
    idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    after = idp.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert after == {}, f"expected domain detached (empty DomainDescription), got {after!r}"

    # the dead binding is also unusable: deleting it again must fail, not no-op.
    # Real AWS answers this with the same InvalidParameterException as the mismatched-owner
    # case above, not ResourceNotFoundException - a deleted domain is graded the same as one
    # that was never attached to this pool, not as one that never existed.
    code2, message2 = _error(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    assert code2 == "InvalidParameterException", f"expected InvalidParameterException, got {code2!r}"
    assert message2 == "No such domain or user pool exists.", f"repeat DeleteUserPoolDomain: message {message2!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _domain_name(ctx) -> str:
    return ctx.unique_name("sim2real-behav-domain-").lower().replace("_", "-")


def _safe_delete_domain(idp, domain: str, pool_id: str) -> None:
    try:
        idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    except ClientError as e:
        # Real AWS answers a delete on an already-deleted domain with InvalidParameterException,
        # not ResourceNotFoundException - both mean "already gone".
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidParameterException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
