"""merge-profiles-self-reference-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-profiles-self-reference-rejected"
GROUP = "overly-permissive"
SERVICES = ["customer-profiles"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergeProfiles rejects a request whose ProfileIdsToBeMerged includes the MainProfileId itself; the profile is untouched."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")

    cp.create_domain(
        DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    main_profile = cp.create_profile(DomainName=domain, FirstName="Solo")["ProfileId"]

    code, message = _error(
        lambda: cp.merge_profiles(
            DomainName=domain, MainProfileId=main_profile, ProfileIdsToBeMerged=[main_profile]
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Request contains duplicated profile ID", (
        f"unexpected self-merge rejection message: {message!r}"
    )

    # effect absent: profile still exists, untouched by the rejected self-merge.
    still_there = cp.batch_get_profile(DomainName=domain, ProfileIds=[main_profile])
    still_there_ids = {p["ProfileId"] for p in still_there.get("Profiles", [])}
    assert still_there_ids == {main_profile}, (
        f"expected {main_profile!r} to survive rejected self-merge, got {still_there_ids!r}"
    )

    # positive control: merging a genuinely different profile into it succeeds.
    other_profile = cp.create_profile(DomainName=domain, FirstName="Other")["ProfileId"]
    cp.merge_profiles(
        DomainName=domain, MainProfileId=main_profile, ProfileIdsToBeMerged=[other_profile]
    )
    gone = _poll_until(
        lambda: cp.batch_get_profile(DomainName=domain, ProfileIds=[other_profile]),
        lambda r: other_profile not in {p["ProfileId"] for p in r.get("Profiles", [])},
        timeout_s=60,
    )
    gone_ids = {p["ProfileId"] for p in gone.get("Profiles", [])}
    assert other_profile not in gone_ids, (
        f"expected {other_profile} merged away, still present: {gone_ids!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
