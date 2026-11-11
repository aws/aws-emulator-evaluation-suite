"""search-profiles-logical-operator-and-or."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-profiles-logical-operator-and-or"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchProfiles LogicalOperator=OR unions matches across keys; AND requires both keys to match the same profile."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    acct1 = ctx.unique_name("sim2real-acct1-")
    acct2 = ctx.unique_name("sim2real-acct2-")
    email1 = f"{ctx.unique_name('sim2real-e1-')}@example.com"
    email2 = f"{ctx.unique_name('sim2real-e2-')}@example.com"

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    p1 = cp.create_profile(DomainName=domain, AccountNumber=acct1, EmailAddress=email1)["ProfileId"]
    p2 = cp.create_profile(DomainName=domain, AccountNumber=acct2, EmailAddress=email2)["ProfileId"]

    or_result = _poll_until(
        lambda: cp.search_profiles(
            DomainName=domain,
            KeyName="_account",
            Values=[acct1],
            AdditionalSearchKeys=[{"KeyName": "_email", "Values": [email2]}],
            LogicalOperator="OR",
        ),
        lambda r: len(r.get("Items", [])) >= 2,
        timeout_s=60,
    )
    or_ids = {i["ProfileId"] for i in or_result["Items"]}
    assert or_ids == {p1, p2}, f"OR must union both keys' matches exactly, got {or_ids} expected {{{p1}, {p2}}}"

    and_result = cp.search_profiles(
        DomainName=domain,
        KeyName="_account",
        Values=[acct1],
        AdditionalSearchKeys=[{"KeyName": "_email", "Values": [email2]}],
        LogicalOperator="AND",
    )
    and_items = and_result.get("Items", [])
    assert and_items == [], (
        f"AND must require both keys to match the same profile, got {[i['ProfileId'] for i in and_items]}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
