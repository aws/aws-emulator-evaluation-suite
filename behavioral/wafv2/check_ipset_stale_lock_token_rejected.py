"""ipset-stale-lock-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ipset-stale-lock-token-rejected"
GROUP = "server-side"
SERVICES = ["wafv2"]

_STALE_LOCK = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIPSet with a stale LockToken fails with WAFOptimisticLockException and the exact message and
    leaves the addresses unchanged; an update with the current LockToken lands and mints a new token.
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-ipset-lock-")
    created = wafv2.create_ip_set(
        Name=name,
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=["10.0.0.0/8"],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Summary"]
    ip_set_id = created["Id"]
    stale_token = created["LockToken"]

    def _cleanup():
        current = wafv2.get_ip_set(Name=name, Scope="REGIONAL", Id=ip_set_id)
        wafv2.delete_ip_set(
            Name=name, Scope="REGIONAL", Id=ip_set_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)

    # Consume the initial LockToken with a real update -- `stale_token` is now stale.
    first_update = wafv2.update_ip_set(
        Name=name,
        Scope="REGIONAL",
        Id=ip_set_id,
        Addresses=["10.0.0.0/8", "192.0.2.0/24"],
        LockToken=stale_token,
    )
    current_token = first_update["NextLockToken"]
    assert current_token != stale_token, (
        f"UpdateIPSet must mint a fresh LockToken, got the same value {current_token!r}"
    )

    # Negative: reusing the now-stale token for a second update is rejected.
    code, message = _error(
        lambda: wafv2.update_ip_set(
            Name=name,
            Scope="REGIONAL",
            Id=ip_set_id,
            Addresses=["203.0.113.0/24"],
            LockToken=stale_token,
        )
    )
    assert code == "WAFOptimisticLockException", code
    assert message == _STALE_LOCK, message

    # Effect absent: the rejected update did not change the addresses.
    after_reject = wafv2.get_ip_set(Name=name, Scope="REGIONAL", Id=ip_set_id)["IPSet"]
    assert after_reject["Addresses"] == ["10.0.0.0/8", "192.0.2.0/24"], after_reject["Addresses"]

    # Positive control: updating with the CURRENT LockToken succeeds.
    second_update = wafv2.update_ip_set(
        Name=name,
        Scope="REGIONAL",
        Id=ip_set_id,
        Addresses=["203.0.113.0/24"],
        LockToken=current_token,
    )
    assert second_update["NextLockToken"] != current_token, (
        "the successful update with the current LockToken must mint a fresh one, "
        f"got the same value {current_token!r}"
    )
    after_success = wafv2.get_ip_set(Name=name, Scope="REGIONAL", Id=ip_set_id)["IPSet"]
    assert after_success["Addresses"] == ["203.0.113.0/24"], (
        f"expected the current-token update to land, got {after_success['Addresses']}"
    )


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises, so
    an emulator accepting what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
