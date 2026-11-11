"""invalid-domain-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-domain-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolDomain binds a valid domain to the pool and unbinds it on delete, and fails with
    InvalidParameterException and its exact message for an uppercase/underscore domain, which stays
    unbound."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    valid_domain = ctx.unique_name("sim2real-behav-cip-domain-").lower()
    c.create_user_pool_domain(Domain=valid_domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda _p=pool_id, _d=valid_domain: _delete_domain_if_bound(c, _d, _p))

    attached = c.describe_user_pool_domain(Domain=valid_domain)["DomainDescription"]
    assert attached.get("UserPoolId") == pool_id, (
        f"positive control: expected valid domain {valid_domain} bound to pool {pool_id}, got {attached.get('UserPoolId')}"
    )

    c.delete_user_pool_domain(Domain=valid_domain, UserPoolId=pool_id)
    detached = c.describe_user_pool_domain(Domain=valid_domain).get("DomainDescription", {})
    assert detached.get("UserPoolId") is None, (
        f"expected valid domain {valid_domain} unbound after delete, got {detached}"
    )

    invalid_domain = "Invalid_Domain_Name"
    code, message = _error(
        lambda: c.create_user_pool_domain(Domain=invalid_domain, UserPoolId=pool_id)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an invalid domain, got {code}"
    )
    expected = (
        "The domain name contains an invalid character. Domain names can only contain lower-case"
        " letters, numbers, and hyphens. Please enter a different name that follows this format:"
        r" ^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    rejected = c.describe_user_pool_domain(Domain=invalid_domain).get("DomainDescription", {})
    assert rejected.get("UserPoolId") is None, (
        f"expected rejected domain {invalid_domain} never bound to any pool, got {rejected}"
    )


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_domain_if_bound(c, domain, pool_id):
    """Teardown for the valid domain: the check deletes it itself, so only a leftover is removed."""
    if c.describe_user_pool_domain(Domain=domain).get("DomainDescription", {}).get("UserPoolId"):
        c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
