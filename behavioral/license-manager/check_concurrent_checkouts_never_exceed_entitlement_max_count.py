"""concurrent-checkouts-never-exceed-entitlement-max-count."""
from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-checkouts-never-exceed-entitlement-max-count"
GROUP = "entitlement-counting"
SERVICES = ["license-manager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Six parallel checkouts against MaxCount=2 grant exactly two with distinct tokens, refuse four with
    NoEntitlementsAllowedException "No Entitlements Allowed.", and ConsumedValue settles at 2.
    """
    lm = ctx.client("license-manager")
    account = ctx.client("sts").get_caller_identity()["Account"]
    sku, fingerprint, arn = _make_license(ctx, lm, max_count=2, overage=False)

    fresh = _usage(lm, arn)
    assert fresh == ("0", "2"), (
        f"a freshly created license reported usage {fresh!r}, expected ('0', '2')"
    )

    def attempt(_):
        try:
            granted = _checkout(ctx, lm, sku, fingerprint, account=account)
            return ("granted", granted["LicenseConsumptionToken"])
        except ClientError as err:
            return ("refused", err.response["Error"])

    with cf.ThreadPoolExecutor(max_workers=_RACERS) as pool:
        outcomes = list(pool.map(attempt, range(_RACERS)))

    granted = [value for kind, value in outcomes if kind == "granted"]
    for token in granted:
        ctx.on_cleanup(lambda token=token: _check_in(lm, token))
    refused = [value for kind, value in outcomes if kind == "refused"]

    assert len(granted) == 2, (
        f"{_RACERS} concurrent checkouts against MaxCount=2 granted {len(granted)}, not 2 "
        f"— the cap must hold under concurrency. Outcomes: {outcomes!r}"
    )
    refused_codes = {error["Code"] for error in refused}
    refused_messages = {error.get("Message") for error in refused}
    assert refused_codes == {"NoEntitlementsAllowedException"}, (
        f"the losing checkouts were refused with {sorted(refused_codes)!r}, expected every "
        f"one of them to be NoEntitlementsAllowedException. Outcomes: {outcomes!r}"
    )
    assert refused_messages == {"No Entitlements Allowed."}, (
        f"the losing checkouts were refused with messages {refused_messages!r}, expected "
        f"exactly 'No Entitlements Allowed.'. Outcomes: {outcomes!r}"
    )
    assert len(set(granted)) == 2, (
        f"the two granted checkouts returned {len(set(granted))} distinct consumption "
        f"token(s); each grant must mint its own"
    )

    settled = _usage(lm, arn)
    assert settled == ("2", "2"), (
        f"after the concurrent burst usage was {settled!r}, expected ('2', '2') — exactly "
        f"the two grants, no more and no fewer"
    )

    for token in granted:
        _rl(lambda token=token: lm.check_in_license(LicenseConsumptionToken=token))
    drained = _usage(lm, arn)
    assert drained == ("0", "2"), (
        f"after checking both granted tokens back in usage was {drained!r}, expected "
        f"('0', '2')"
    )


_ENTITLEMENT = "sim2real-seats"
_RACERS = 6


def _rl(fn, *, tries=12):
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


def _ensure_service_role(ctx) -> None:
    """CreateLicense needs License Manager's service-linked role; create it if it is absent.

    IAM answers InvalidInput when the role already exists."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="license-manager.amazonaws.com")
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidInput":
            raise


def _make_license(ctx, lm, *, max_count, overage, ttl_minutes=60,
                  unit="Count", entitlement=_ENTITLEMENT):
    """Create a self-managed license this check owns outright; return (sku, fingerprint, arn).

    Every handle is derived: the beneficiary is the caller's own account, the home region
    is ctx.region, and the SKU / issuer / name are unique per run so a concurrent run
    in the same account cannot collide on the (ProductSKU, KeyFingerprint) checkout key.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    _ensure_service_role(ctx)
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
            # A just-created service-linked role (this run's or a concurrent run's) takes a few
            # seconds to reach License Manager.
            if (err.response["Error"]["Code"] != "AccessDeniedException"
                    or not err.response["Error"].get("Message", "").startswith("Service role not found.")
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2.0)
    arn, version = created["LicenseArn"], created["Version"]
    ctx.on_cleanup(lambda: _rl(
        lambda: lm.delete_license(LicenseArn=arn, SourceVersion=version)))
    fingerprint = _rl(
        lambda: lm.get_license(LicenseArn=arn))["License"]["Issuer"]["KeyFingerprint"]
    return sku, fingerprint, arn


def _checkout(ctx, lm, sku, fingerprint, *, account=None, value="1",
              name=_ENTITLEMENT, unit="Count"):
    """Check one entitlement value out.

    `account` is resolved from STS when not supplied. Callers that run this from several
    threads MUST supply it: botocore client construction is not thread-safe, so no worker
    thread may be the first to ask ctx for a client.
    """
    if account is None:
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


def _expect_refusal(fn, code, what):
    """Run fn expecting exactly `code`. Success, or any other code, is a FAIL."""
    try:
        result = fn()
    except ClientError as err:
        actual = err.response["Error"]["Code"]
        assert actual == code, (
            f"{what} was refused with {actual!r} "
            f"({err.response['Error'].get('Message')!r}), expected exactly {code!r}"
        )
        return err
    raise AssertionError(
        f"{what} SUCCEEDED and returned {result!r}; real AWS refuses it with {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
