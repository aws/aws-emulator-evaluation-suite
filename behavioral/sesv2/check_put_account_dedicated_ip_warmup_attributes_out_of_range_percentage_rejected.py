"""put-account-dedicated-ip-warmup-attributes-out-of-range-percentage-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-dedicated-ip-warmup-attributes-out-of-range-percentage-rejected"
GROUP = "overly-permissive"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """PutDedicatedIpWarmupAttributes rejects a warmup percentage outside 0-100 with
    BadRequestException instead of clamping or accepting it.
    """
    ses = ctx.client("sesv2")
    # The percentage lives on per-IP PutDedicatedIpWarmupAttributes; a never-owned TEST-NET-1 IP
    # (RFC 5737) separates shape validation from NotFoundException without a paid dedicated IP.
    fake_ip = "192.0.2.123"

    out_of_range = ("BadRequestException", "Warmup Percentage must be between 0 and 100.")
    too_high = _error(
        lambda: ses.put_dedicated_ip_warmup_attributes(Ip=fake_ip, WarmupPercentage=150)
    )
    assert too_high == out_of_range, f"expected {out_of_range!r}, got {too_high!r}"

    too_low = _error(
        lambda: ses.put_dedicated_ip_warmup_attributes(Ip=fake_ip, WarmupPercentage=-5)
    )
    assert too_low == out_of_range, f"expected {out_of_range!r}, got {too_low!r}"

    # Positive control: an in-range percentage passes validation and fails on existence instead,
    # so the BadRequestException above is about the value, not a blanket rejection.
    in_range = _error(
        lambda: ses.put_dedicated_ip_warmup_attributes(Ip=fake_ip, WarmupPercentage=50)
    )
    expected_missing = (
        "NotFoundException",
        f"Could not find dedicated IP <{fake_ip}> under this account.",
    )
    assert in_range == expected_missing, f"expected {expected_missing!r}, got {in_range!r}"

    # The per-IP call has no success path without a paid dedicated IP, so the account-level
    # toggle, read back via GetAccount, shows warmup-attribute calls succeed in general.
    account_before = ses.get_account()
    original_auto_warmup = bool(account_before.get("DedicatedIpAutoWarmupEnabled", False))
    ctx.on_cleanup(
        lambda: ses.put_account_dedicated_ip_warmup_attributes(
            AutoWarmupEnabled=original_auto_warmup
        )
    )
    ses.put_account_dedicated_ip_warmup_attributes(AutoWarmupEnabled=not original_auto_warmup)
    account_after = ses.get_account()
    assert account_after["DedicatedIpAutoWarmupEnabled"] == (not original_auto_warmup), (
        f"expected DedicatedIpAutoWarmupEnabled={not original_auto_warmup}, "
        f"got {account_after.get('DedicatedIpAutoWarmupEnabled')}"
    )


def _error(fn):
    """Return the rejected call's (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
