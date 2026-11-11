"""concurrent-profile-key-addition-no-lost-update."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-profile-key-addition-no-lost-update"
GROUP = "concurrency"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two AddProfileKey calls on distinct KeyNames for the same profile, fired concurrently, both persist (no lost update)."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    value1 = ctx.unique_name("sim2real-ctr-")
    value2 = ctx.unique_name("sim2real-zd-")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    profile_id = cp.create_profile(DomainName=domain)["ProfileId"]

    def _add_ctr():
        cp.add_profile_key(
            DomainName=domain, ProfileId=profile_id, KeyName="_ctrContactId", Values=[value1]
        )

    def _add_zendesk():
        cp.add_profile_key(
            DomainName=domain, ProfileId=profile_id, KeyName="_zendeskUserId", Values=[value2]
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_add_ctr)
        f2 = pool.submit(_add_zendesk)
        f1.result()
        f2.result()

    found_ctr = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_ctrContactId", Values=[value1]),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    found_zendesk = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_zendeskUserId", Values=[value2]),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    ctr_ids = {i["ProfileId"] for i in found_ctr["Items"]}
    assert profile_id in ctr_ids, (
        f"_ctrContactId={value1!r} added concurrently was lost: profile {profile_id} "
        f"not among search hits {ctr_ids!r}"
    )
    zendesk_ids = {i["ProfileId"] for i in found_zendesk["Items"]}
    assert profile_id in zendesk_ids, (
        f"_zendeskUserId={value2!r} added concurrently was lost: profile {profile_id} "
        f"not among search hits {zendesk_ids!r}"
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
