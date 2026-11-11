"""op-contract-update-user-pool-domain."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-update-user-pool-domain"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolDomain flips a prefix domain's managed-login branding version, and
    is rejected when the Domain given isn't associated with the UserPoolId."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-upd-domain-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2realbehavdomain").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    status = _poll_until(
        lambda: cognito.describe_user_pool_domain(Domain=domain)
        .get("DomainDescription", {})
        .get("Status"),
        predicate=lambda s: s == "ACTIVE",
        timeout_s=90,
        interval_s=5,
    )
    if status != "ACTIVE":
        raise AssertionError(
            f"domain never reached ACTIVE (last status={status!r})",
        )

    cognito.update_user_pool_domain(Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=2)

    described = _poll_until(
        lambda: cognito.describe_user_pool_domain(Domain=domain)["DomainDescription"],
        predicate=lambda d: d.get("ManagedLoginVersion") == 2,
        timeout_s=90,
        interval_s=5,
    )
    assert described.get("ManagedLoginVersion") == 2, (
        f"expected ManagedLoginVersion=2 after update, got {described.get('ManagedLoginVersion')!r}"
    )

    # Error boundary: a domain that legitimately exists, but under a DIFFERENT user pool, is
    # rejected as not associated with this UserPoolId. A domain name that was simply never
    # created anywhere would let a target pass this without tracking per-pool ownership at all.
    other_pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-upd-domain-other-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=other_pool_id))

    other_domain = ctx.unique_name("sim2realbehavdomainother").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=other_domain, UserPoolId=other_pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=other_domain, UserPoolId=other_pool_id))

    other_status = _poll_until(
        lambda: cognito.describe_user_pool_domain(Domain=other_domain)
        .get("DomainDescription", {})
        .get("Status"),
        predicate=lambda s: s == "ACTIVE",
        timeout_s=90,
        interval_s=5,
    )
    if other_status != "ACTIVE":
        raise AssertionError(
            f"other pool's domain never reached ACTIVE (last status={other_status!r})",
        )

    code, message = _error(
        lambda: cognito.update_user_pool_domain(
            Domain=other_domain,
            UserPoolId=pool_id,
            ManagedLoginVersion=2,
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException updating a domain owned by a different pool, got {code!r}"
    )
    expected = "The domain is not configured for this user pool."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unaffected = cognito.describe_user_pool_domain(Domain=other_domain)["DomainDescription"]
    assert unaffected.get("ManagedLoginVersion") != 2, (
        "cross-pool update must not have taken effect, but ManagedLoginVersion="
        f"{unaffected.get('ManagedLoginVersion')!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
