"""user-pool-domain-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "user-pool-domain-lifecycle"
GROUP = 'pool-level-lifecycle'
SERVICES = ['cognito-idp']


def _poll_until(fn, pred, timeout_s, interval_s, description):
    """Poll fn() until pred(result) is truthy or the deadline passes; returns the
    last result on success, else raises AssertionError. Real AWS domain
    provisioning (CREATING -> ACTIVE) lags; an emulator answers immediately."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Prefix domain: create -> describe (ACTIVE) -> update (branding version) ->
    delete; unusable (not ACTIVE / not found) once deleted."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    domain = ctx.unique_name("sim2real-behav-cip-domain-").lower()

    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=1)
    ctx.on_cleanup(
        lambda _p=pool_id, _d=domain: _delete_unless_gone(
            lambda: c.delete_user_pool_domain(Domain=_d, UserPoolId=_p)
        )
    )

    desc = _poll_until(
        lambda: c.describe_user_pool_domain(Domain=domain)["DomainDescription"],
        lambda d: d.get("Status") == "ACTIVE",
        timeout_s=120,
        interval_s=5,
        description="domain ACTIVE",
    )
    assert desc["UserPoolId"] == pool_id, (
        f"expected domain bound to pool {pool_id}, got {desc['UserPoolId']!r}"
    )
    assert desc.get("ManagedLoginVersion") == 1, (
        f"expected ManagedLoginVersion 1 after create, got {desc.get('ManagedLoginVersion')!r}"
    )

    c.update_user_pool_domain(Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=2)
    desc2 = _poll_until(
        lambda: c.describe_user_pool_domain(Domain=domain)["DomainDescription"],
        lambda d: d.get("ManagedLoginVersion") == 2,
        timeout_s=120,
        interval_s=5,
        description="domain branding version updated to 2",
    )
    assert desc2["ManagedLoginVersion"] == 2, (
        f"expected ManagedLoginVersion 2 after update, got {desc2['ManagedLoginVersion']!r}"
    )

    c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    after = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert after.get("Status") != "ACTIVE" and after.get("UserPoolId") != pool_id, (
        f"domain still usable/attached after delete: {after}"
    )

    # the dead domain is also unusable: a mutation naming it is rejected, not silently accepted
    code, message = _error(
        lambda: c.update_user_pool_domain(Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=1)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted domain, got {code!r}"
    )
    expected = "User pool domain was not found."
    assert message == expected, (
        f"updating a deleted domain: expected message {expected!r}, got {message!r}"
    )


def _delete_unless_gone(fn):
    """Teardown for the domain the check itself deletes: AWS's refusal naming it gone is success."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        e = err.response["Error"]
        if (e["Code"], e.get("Message")) != (
            "InvalidParameterException",
            "No such domain or user pool exists.",
        ):
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
