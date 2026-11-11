"""entitlement-consumed-count-tracks-checkout-and-checkin."""
from __future__ import annotations

import datetime as dt
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "entitlement-consumed-count-tracks-checkout-and-checkin"
GROUP = "entitlement-counting"
SERVICES = ["license-manager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLicenseUsage's ConsumedValue moves 0 -> 1 -> 2 -> 1 -> 0 across two checkouts with distinct tokens
    and two check-ins, while MaxCount stays 3.
    """
    lm = ctx.client("license-manager")
    sku, fingerprint, arn = _make_license(ctx, lm, max_count=3, overage=False)

    fresh = _usage(lm, arn)
    assert fresh == ("0", "3"), (
        f"a freshly created license reported usage {fresh!r}, expected ('0', '3')"
    )

    first = _checkout(ctx, lm, sku, fingerprint)
    tok_a = first["LicenseConsumptionToken"]
    ctx.on_cleanup(lambda: _check_in(lm, tok_a))
    assert first["EntitlementsAllowed"] == [
        {"Name": _ENTITLEMENT, "Value": "1", "Unit": "Count"}
    ], f"first checkout allowed {first['EntitlementsAllowed']!r}, expected one Count of 1"
    after_one = _usage(lm, arn)
    assert after_one == ("1", "3"), (
        f"after one checkout usage was {after_one!r}, expected ('1', '3')"
    )

    second = _checkout(ctx, lm, sku, fingerprint)
    tok_b = second["LicenseConsumptionToken"]
    ctx.on_cleanup(lambda: _check_in(lm, tok_b))
    assert tok_b != tok_a, (
        f"the second checkout reissued the first consumption token {tok_a!r} — each "
        f"checkout must mint a distinct token"
    )
    after_two = _usage(lm, arn)
    assert after_two == ("2", "3"), (
        f"after two checkouts usage was {after_two!r}, expected ('2', '3') — the "
        f"second checkout must increment the counter, not replace it"
    )

    _rl(lambda: lm.check_in_license(LicenseConsumptionToken=tok_a))
    after_first_checkin = _usage(lm, arn)
    assert after_first_checkin == ("1", "3"), (
        f"after checking the first token back in usage was {after_first_checkin!r}, "
        f"expected ('1', '3')"
    )

    _rl(lambda: lm.check_in_license(LicenseConsumptionToken=tok_b))
    after_both_checkins = _usage(lm, arn)
    assert after_both_checkins == ("0", "3"), (
        f"after checking both tokens back in usage was {after_both_checkins!r}, "
        f"expected ('0', '3')"
    )


_ENTITLEMENT = "sim2real-seats"


def _rl(fn, *, tries=8):
    """Bounded retry over License Manager's own API call limit (RateLimitExceededException).

    License Manager throttles CreateLicense/CheckoutLicense aggressively; a throttle is
    our call rate, never the service contract, so it is retried and never asserted on.
    """
    for attempt in range(tries):
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "RateLimitExceededException":
                raise
            time.sleep(2 + 2 * attempt)
    return fn()


def _iso(when) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_license(ctx, lm, *, max_count, overage, ttl_minutes=60,
                  unit="Count", entitlement=_ENTITLEMENT):
    """Create a self-managed license this check owns outright; return (sku, fingerprint, arn).

    Every handle is derived: the beneficiary is the caller's own account, the home region
    is ctx.region, and the SKU / issuer / name are unique per run so a concurrent run
    in the same account cannot collide on the (ProductSKU, KeyFingerprint) checkout key.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    now = dt.datetime.now(dt.timezone.utc)
    sku = ctx.unique_name("sim2real-behav-lm-sku-")
    created = _rl(lambda: lm.create_license(
        LicenseName=ctx.unique_name("sim2real-behav-lm-lic-"),
        ProductName="sim2real-behav-lm-product",
        ProductSKU=sku,
        Issuer={"Name": ctx.unique_name("sim2real-behav-lm-issuer-")},
        HomeRegion=ctx.region,
        Validity={"Begin": _iso(now), "End": _iso(now + dt.timedelta(days=1))},
        Entitlements=[{"Name": entitlement, "Unit": unit, "MaxCount": max_count,
                       "Overage": overage, "AllowCheckIn": True}],
        Beneficiary=account,
        ConsumptionConfiguration={
            "RenewType": "None",
            "ProvisionalConfiguration": {"MaxTimeToLiveInMinutes": ttl_minutes},
        },
        ClientToken=str(uuid.uuid4()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))
    arn, version = created["LicenseArn"], created["Version"]
    ctx.on_cleanup(lambda: _rl(
        lambda: lm.delete_license(LicenseArn=arn, SourceVersion=version)))
    fingerprint = _rl(
        lambda: lm.get_license(LicenseArn=arn))["License"]["Issuer"]["KeyFingerprint"]
    return sku, fingerprint, arn


def _checkout(ctx, lm, sku, fingerprint, *, value="1", name=_ENTITLEMENT, unit="Count"):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return _rl(lambda: lm.checkout_license(
        ProductSKU=sku, CheckoutType="PROVISIONAL", KeyFingerprint=fingerprint,
        Entitlements=[{"Name": name, "Unit": unit, "Value": value}],
        ClientToken=str(uuid.uuid4()), Beneficiary=account))


def _check_in(lm, token) -> None:
    """Check a consumption token back in; a token already checked in is not an error here."""
    try:
        _rl(lambda: lm.check_in_license(LicenseConsumptionToken=token))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _usage(lm, arn, *, name=_ENTITLEMENT):
    """Return (ConsumedValue, MaxCount) for one entitlement of a license."""
    usages = _rl(
        lambda: lm.get_license_usage(LicenseArn=arn))["LicenseUsage"]["EntitlementUsages"]
    for entry in usages:
        if entry["Name"] == name:
            return entry["ConsumedValue"], entry.get("MaxCount")
    raise AssertionError(
        f"GetLicenseUsage reported no entitlement named {name!r}; it returned {usages!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
