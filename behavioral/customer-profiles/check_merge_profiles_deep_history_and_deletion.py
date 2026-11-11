"""merge-profiles-deep-history-and-deletion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "merge-profiles-deep-history-and-deletion"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergeProfiles records a MERGED history entry on the surviving profile and removes the
    merged-away profile so that it is both absent from a read and rejected by a mutation."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")

    cp.create_domain(
        DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    main_profile = cp.create_profile(DomainName=domain, FirstName="Main")["ProfileId"]
    merged_profile = cp.create_profile(DomainName=domain, FirstName="Merged")["ProfileId"]

    cp.merge_profiles(
        DomainName=domain, MainProfileId=main_profile, ProfileIdsToBeMerged=[merged_profile]
    )

    history = _poll_until(
        lambda: cp.list_profile_history_records(DomainName=domain, ProfileId=main_profile),
        lambda r: any(x["ActionType"] == "MERGED" for x in r.get("ProfileHistoryRecords", [])),
        timeout_s=60,
    )
    action_types = [r["ActionType"] for r in history["ProfileHistoryRecords"]]
    assert "MERGED" in action_types, (
        f"expected a MERGED history record on surviving profile {main_profile}, got {action_types!r}"
    )

    after_merge = _poll_until(
        lambda: cp.batch_get_profile(DomainName=domain, ProfileIds=[merged_profile]),
        lambda r: merged_profile not in {p["ProfileId"] for p in r.get("Profiles", [])},
        timeout_s=60,
    )
    survivors = {p["ProfileId"] for p in after_merge.get("Profiles", [])}
    assert merged_profile not in survivors, (
        f"expected {merged_profile} merged away and absent from batch_get_profile, still present: {survivors!r}"
    )

    # gone AND unusable: a mutation against the merged-away id is rejected, specifically.
    code, message = _error(
        lambda: cp.update_profile(DomainName=domain, ProfileId=merged_profile, FirstName="Ghost")
    )
    assert code == "ResourceNotFoundException", (
        f"expected UpdateProfile on merged-away {merged_profile} to be rejected with "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Profile with profileId {merged_profile} is not found in the domain", (
        f"unexpected UpdateProfile message for merged-away {merged_profile}: {message!r}"
    )

    # deep history: the merged-away profile's own id is unqueryable, not merely absent from a
    # batch read — its history is gone with it, on a second independent operation.
    history_code, history_message = _error(
        lambda: cp.list_profile_history_records(DomainName=domain, ProfileId=merged_profile)
    )
    assert history_code == "ResourceNotFoundException", (
        f"expected ListProfileHistoryRecords on merged-away {merged_profile} to be rejected with "
        f"ResourceNotFoundException, got {history_code!r}"
    )
    assert history_message == f"Profile {merged_profile} not found in domain {domain}", (
        f"unexpected ListProfileHistoryRecords message for merged-away {merged_profile}: "
        f"{history_message!r}"
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
