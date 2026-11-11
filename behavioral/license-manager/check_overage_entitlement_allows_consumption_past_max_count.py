"""overage-entitlement-allows-consumption-past-max-count."""
from __future__ import annotations

import datetime as dt
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overage-entitlement-allows-consumption-past-max-count"
GROUP = "entitlement-counting"
SERVICES = ["license-manager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With Overage=True two checkouts against MaxCount=1 are granted with distinct tokens and ConsumedValue
    reads 2 of 1; with Overage=False the second checkout raises NoEntitlementsAllowedException and
    ConsumedValue stays 1.
    """
    lm = ctx.client("license-manager")
    over_sku, over_fp, over_arn = _make_license(ctx, lm, max_count=1, overage=True)
    hard_sku, hard_fp, hard_arn = _make_license(ctx, lm, max_count=1, overage=False)

    over_first = _checkout(ctx, lm, over_sku, over_fp)
    over_tok_a = over_first["LicenseConsumptionToken"]
    ctx.on_cleanup(lambda: _check_in(lm, over_tok_a))
    at_max = _usage(lm, over_arn)
    assert at_max == ("1", "1"), (
        f"after one checkout the overage license reported {at_max!r}, expected ('1', '1')"
    )

    over_second = _checkout(ctx, lm, over_sku, over_fp)
    over_tok_b = over_second["LicenseConsumptionToken"]
    ctx.on_cleanup(lambda: _check_in(lm, over_tok_b))
    assert over_second["EntitlementsAllowed"] == [
        {"Name": _ENTITLEMENT, "Value": "1", "Unit": "Count"}
    ], (
        f"the overage checkout allowed {over_second['EntitlementsAllowed']!r}, expected "
        f"one Count of 1"
    )
    over = _usage(lm, over_arn)
    assert over == ("2", "1"), (
        f"with Overage=True the second checkout should have taken consumption past the "
        f"ceiling to ('2', '1'), but usage was {over!r}"
    )
    assert over_tok_b != over_tok_a, (
        f"the overage checkout reissued the first consumption token {over_tok_a!r}"
    )

    # The contrast that isolates Overage: an otherwise identical license refuses this.
    hard_first = _checkout(ctx, lm, hard_sku, hard_fp)
    hard_tok = hard_first["LicenseConsumptionToken"]
    ctx.on_cleanup(lambda: _check_in(lm, hard_tok))
    _expect_refusal(
        lambda: _checkout(ctx, lm, hard_sku, hard_fp),
        *_NO_ENTITLEMENTS,
        "the same second checkout against an otherwise identical Overage=False license",
    )
    hard = _usage(lm, hard_arn)
    assert hard == ("1", "1"), (
        f"the Overage=False license should have stayed at its ceiling ('1', '1'), but "
        f"usage was {hard!r}"
    )

    _rl(lambda: lm.check_in_license(LicenseConsumptionToken=over_tok_a))
    _rl(lambda: lm.check_in_license(LicenseConsumptionToken=over_tok_b))
    drained = _usage(lm, over_arn)
    assert drained == ("0", "1"), (
        f"after checking both overage tokens back in usage was {drained!r}, expected "
        f"('0', '1') — overage consumption must decrement like any other"
    )


_ENTITLEMENT = "sim2real-seats"
# The exact (code, message) AWS answers.
_NO_ENTITLEMENTS = ("NoEntitlementsAllowedException", "No Entitlements Allowed.")


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


def _ensure_service_role(ctx) -> bool:
    """CreateLicense needs License Manager's service-linked role; create it if it is absent.

    Returns True when the role was just created, so the caller waits out its propagation.
    """
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="license-manager.amazonaws.com")
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidInput":
            raise
        return False
    return True


def _make_license(ctx, lm, *, max_count, overage, ttl_minutes=60,
                  unit="Count", entitlement=_ENTITLEMENT):
    """Create a self-managed license this check owns outright; return (sku, fingerprint, arn).

    Every handle is derived: the beneficiary is the caller's own account, the home region
    is ctx.region, and the SKU / issuer / name are unique per run so a concurrent run
    in the same account cannot collide on the (ProductSKU, KeyFingerprint) checkout key.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    fresh_role = _ensure_service_role(ctx)
    now = dt.datetime.now(dt.timezone.utc)
    sku = ctx.unique_name("sim2real-behav-lm-sku-")
    request = dict(
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
    )
    deadline = time.monotonic() + 60.0
    while True:
        try:
            created = _rl(lambda: lm.create_license(**request))
            break
        except ClientError as err:
            # A just-created service-linked role takes a few seconds to reach License Manager.
            if (err.response["Error"]["Code"] != "AccessDeniedException" or not fresh_role
                    or time.monotonic() >= deadline):
                raise
            time.sleep(5.0)
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


def _expect_refusal(fn, code, message, what):
    """Run fn expecting exactly `code` with exactly `message`. Success, or any other code or
    message, is a FAIL."""
    try:
        result = fn()
    except ClientError as err:
        actual = err.response["Error"]["Code"]
        actual_message = err.response["Error"].get("Message")
        assert actual == code, (
            f"{what} was refused with {actual!r} "
            f"({actual_message!r}), expected exactly {code!r}"
        )
        assert actual_message == message, (
            f"{what} was refused with message {actual_message!r}, expected exactly {message!r}"
        )
        return err
    raise AssertionError(
        f"{what} SUCCEEDED and returned {result!r}; real AWS refuses it with {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
