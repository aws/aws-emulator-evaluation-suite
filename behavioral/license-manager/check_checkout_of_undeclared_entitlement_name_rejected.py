"""checkout-of-undeclared-entitlement-name-rejected."""
from __future__ import annotations

import datetime as dt
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "checkout-of-undeclared-entitlement-name-rejected"
GROUP = "entitlement-counting"
SERVICES = ["license-manager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckoutLicense for an entitlement name the license never declared raises
    NoEntitlementsAllowedException and consumes nothing, while the declared name on the same license is
    granted and ConsumedValue becomes 1.
    """
    lm = ctx.client("license-manager")
    sku, fingerprint, arn = _make_license(ctx, lm, max_count=2, overage=False)

    fresh = _usage(lm, arn)
    assert fresh == ("0", "2"), (
        f"a freshly created license reported usage {fresh!r}, expected ('0', '2')"
    )

    _expect_refusal(
        lambda: _checkout(ctx, lm, sku, fingerprint,
                          name=_ENTITLEMENT + "-never-declared"),
        *_NO_ENTITLEMENTS,
        f"a checkout of {_ENTITLEMENT + '-never-declared'!r}, which this license "
        f"does not declare",
    )
    after_refusal = _usage(lm, arn)
    assert after_refusal == ("0", "2"), (
        f"the refused checkout of an undeclared entitlement moved usage to "
        f"{after_refusal!r}; it must still read ('0', '2')"
    )

    # Positive control: the declared name, same call shape, is granted and counted.
    granted = _checkout(ctx, lm, sku, fingerprint)
    token = granted["LicenseConsumptionToken"]
    ctx.on_cleanup(lambda: _check_in(lm, token))
    assert granted["EntitlementsAllowed"] == [
        {"Name": _ENTITLEMENT, "Value": "1", "Unit": "Count"}
    ], (
        f"the declared entitlement was allowed as {granted['EntitlementsAllowed']!r}, "
        f"expected one Count of 1 for {_ENTITLEMENT!r}"
    )
    after_grant = _usage(lm, arn)
    assert after_grant == ("1", "2"), (
        f"after the declared checkout usage was {after_grant!r}, expected ('1', '2')"
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
