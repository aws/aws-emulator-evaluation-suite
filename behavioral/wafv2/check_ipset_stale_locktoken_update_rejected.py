"""ipset-stale-locktoken-update-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ipset-stale-locktoken-update-rejected"
GROUP = "concurrency"
SERVICES = ["wafv2"]

_STALE_LOCK = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIPSet with a stale LockToken fails with WAFOptimisticLockException and the exact message,
    leaving the addresses and LockToken unchanged; an update with the current token lands and
    advances it.
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-ipset-")
    scope = "REGIONAL"

    created = wafv2.create_ip_set(
        Name=name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=["10.1.0.0/24"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    summary = created["Summary"]
    ip_set_id = summary["Id"]
    stale_token = summary["LockToken"]

    def _cleanup():
        try:
            cur = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
            wafv2.delete_ip_set(Name=name, Scope=scope, Id=ip_set_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    # First, legitimate update using the correct (initial) token: moves the token
    # forward, making `stale_token` stale for any further call.
    update1 = wafv2.update_ip_set(
        Name=name, Scope=scope, Id=ip_set_id, Addresses=["10.2.0.0/24"], LockToken=stale_token
    )
    current_token = update1["NextLockToken"]

    # Break exactly one thing: reuse the now-stale `stale_token` for a second update.
    holder = {}

    def _attempt_stale_update():
        holder["resp"] = wafv2.update_ip_set(
            Name=name, Scope=scope, Id=ip_set_id, Addresses=["10.3.0.0/24"], LockToken=stale_token
        )

    code, message = _error(_attempt_stale_update)
    assert code == "WAFOptimisticLockException", f"expected WAFOptimisticLockException, got {code}"
    assert message == _STALE_LOCK, message

    # Effect must be absent: the rejected 10.3.0.0/24 write never landed.
    after_reject = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    assert after_reject["IPSet"]["Addresses"] == ["10.2.0.0/24"], (
        f"stale-token update leaked through: {after_reject['IPSet']['Addresses']}"
    )
    assert after_reject["LockToken"] == current_token, (
        f"expected LockToken to remain {current_token!r} after the rejected update, "
        f"got {after_reject['LockToken']!r}"
    )

    # Positive control in the same file: the same kind of update succeeds when it
    # uses the current (non-stale) LockToken.
    update2 = wafv2.update_ip_set(
        Name=name, Scope=scope, Id=ip_set_id, Addresses=["10.4.0.0/24"], LockToken=current_token
    )
    assert update2["NextLockToken"] != current_token, (
        f"expected the successful update to advance the LockToken past {current_token!r}, "
        f"got {update2['NextLockToken']!r}"
    )
    after_success = wafv2.get_ip_set(Name=name, Scope=scope, Id=ip_set_id)
    assert after_success["IPSet"]["Addresses"] == ["10.4.0.0/24"], (
        f"expected the restored update to land as ['10.4.0.0/24'], "
        f"got {after_success['IPSet']['Addresses']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
