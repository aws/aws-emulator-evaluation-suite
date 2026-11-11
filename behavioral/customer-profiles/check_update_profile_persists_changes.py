"""update-profile-persists-changes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-profile-persists-changes"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateProfile's field mutation is durably persisted and visible through BatchGetProfile."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    profile_id = cp.create_profile(DomainName=domain, FirstName="Old")["ProfileId"]

    cp.update_profile(DomainName=domain, ProfileId=profile_id, FirstName="New")

    _poll_until(
        lambda: cp.batch_get_profile(DomainName=domain, ProfileIds=[profile_id]),
        lambda r: r.get("Profiles") and r["Profiles"][0].get("FirstName") == "New",
        timeout_s=30,
    )

    # A fresh, independent call after the poll succeeds — not the memoized poll
    # result, whose own predicate already guaranteed the value and so could
    # never fail here.
    confirmed = cp.batch_get_profile(DomainName=domain, ProfileIds=[profile_id])
    confirmed_profiles = confirmed.get("Profiles") or []
    got = confirmed_profiles[0].get("FirstName") if confirmed_profiles else None
    assert got == "New", f"expected persisted FirstName='New', got {got!r}"


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
