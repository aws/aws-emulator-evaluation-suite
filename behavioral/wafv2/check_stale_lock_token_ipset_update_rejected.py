"""stale-lock-token-ipset-update-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stale-lock-token-ipset-update-rejected"
GROUP = "server-side"
SERVICES = ["wafv2"]


_OPTIMISTIC_LOCK_MESSAGE = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIPSet with a LockToken a prior update consumed fails with WAFOptimisticLockException and the
    exact message, leaving addresses and LockToken unchanged; an update with the current LockToken
    returns a NextLockToken and lands.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-stalelock-")

    created = wafv2.create_ip_set(
        Name=name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=["192.0.2.4/32"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ip_set_id = created["Summary"]["Id"]
    stale_lock_token = created["Summary"]["LockToken"]
    ctx.on_cleanup(
        lambda: wafv2.delete_ip_set(
            Name=name,
            Scope=scope,
            Id=ip_set_id,
            LockToken=wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)["LockToken"],
        )
    )

    # Advance the IPSet once, which invalidates stale_lock_token.
    advanced = wafv2.update_ip_set(
        Name=name,
        Scope=scope,
        Id=ip_set_id,
        Addresses=["192.0.2.4/32", "198.51.100.8/32"],
        LockToken=stale_lock_token,
    )
    current_lock_token = advanced["NextLockToken"]

    # Attempt a second update reusing the now-stale token.
    code, message = _error_code(
        lambda: wafv2.update_ip_set(
            Name=name,
            Scope=scope,
            Id=ip_set_id,
            Addresses=["203.0.113.9/32"],
            LockToken=stale_lock_token,
        )
    )
    assert code == "WAFOptimisticLockException", f"expected WAFOptimisticLockException, got {code!r}"
    assert message == _OPTIMISTIC_LOCK_MESSAGE, message

    # The effect of the rejected update must be absent: addresses are unchanged.
    after_reject = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    assert sorted(after_reject["IPSet"]["Addresses"]) == ["192.0.2.4/32", "198.51.100.8/32"], (
        "the rejected stale-token update must not have modified the IPSet's addresses"
    )

    # Positive control: an update using the correct current LockToken succeeds.
    assert after_reject["LockToken"] == current_lock_token, (
        f"expected the read-back LockToken to equal {current_lock_token!r}, "
        f"got {after_reject['LockToken']!r}"
    )
    final = wafv2.update_ip_set(
        Name=name,
        Scope=scope,
        Id=ip_set_id,
        Addresses=["203.0.113.9/32"],
        LockToken=current_lock_token,
    )
    assert "NextLockToken" in final, f"expected NextLockToken in response, got {final!r}"
    after_success = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    assert after_success["IPSet"]["Addresses"] == ["203.0.113.9/32"], (
        f"expected addresses ['203.0.113.9/32'] after the current-token update, "
        f"got {after_success['IPSet']['Addresses']!r}"
    )


def _error_code(fn) -> tuple[str, str | None]:
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
