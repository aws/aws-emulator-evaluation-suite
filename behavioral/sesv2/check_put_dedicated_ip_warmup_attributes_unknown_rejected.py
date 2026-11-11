"""put-dedicated-ip-warmup-attributes-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dedicated-ip-warmup-attributes-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutDedicatedIpWarmupAttributes for an IP that is not a dedicated IP owned by the
    account is rejected with NotFoundException, while a legitimate warm-up-attribute call
    in the same family (account-level auto warm-up) still succeeds."""
    sesv2 = ctx.client("sesv2")
    bogus_ip = "198.51.100.88"  # TEST-NET-2 (RFC 5737), never a real dedicated IP

    err = _error(
        lambda: sesv2.put_dedicated_ip_warmup_attributes(Ip=bogus_ip, WarmupPercentage=50)
    )
    expected = ("NotFoundException", f"Could not find dedicated IP <{bogus_ip}> under this account.")
    assert err == expected, (
        f"PutDedicatedIpWarmupAttributes for an unowned IP returned {err!r}, expected {expected!r}"
    )

    # effect absent: the rejected call did not fabricate ownership of the bogus IP
    owned_ips = [ip["Ip"] for ip in sesv2.get_dedicated_ips().get("DedicatedIps", [])]
    assert bogus_ip not in owned_ips, (
        f"{bogus_ip!r} appears in GetDedicatedIps after a rejected warm-up call: {owned_ips!r}"
    )

    account_before = sesv2.get_account()
    original_auto_warmup = bool(account_before.get("DedicatedIpAutoWarmupEnabled", False))
    ctx.on_cleanup(
        lambda: sesv2.put_account_dedicated_ip_warmup_attributes(
            AutoWarmupEnabled=original_auto_warmup
        )
    )

    # positive control: a valid warm-up-attribute call in the same family succeeds. (A true
    # same-operation control would need a real dedicated IP the account owns; standalone
    # dedicated IPs are no longer provisionable for new accounts, so this account-level
    # sibling call is the closest reachable proof that PutDedicatedIpWarmupAttributes's API
    # surface is not rejecting everything.)
    sesv2.put_account_dedicated_ip_warmup_attributes(AutoWarmupEnabled=not original_auto_warmup)
    account_after = sesv2.get_account()
    assert account_after["DedicatedIpAutoWarmupEnabled"] == (not original_auto_warmup), (
        f"account-level auto-warmup did not flip to {not original_auto_warmup!r}: "
        f"{account_after.get('DedicatedIpAutoWarmupEnabled')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
