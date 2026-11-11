"""profile-key-history-records-add-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "profile-key-history-records-add-and-delete"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AddProfileKey/DeleteProfileKey each write exactly one audit trail entry (ADDED_PROFILE_KEY,
    DELETED_PROFILE_KEY, both retained afterwards) and each flips whether the profile is
    discoverable via SearchProfiles by that key."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    contact_value = ctx.unique_name("sim2real-contact-")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    profile_id = cp.create_profile(DomainName=domain)["ProfileId"]

    cp.add_profile_key(
        DomainName=domain, ProfileId=profile_id, KeyName="_ctrContactId", Values=[contact_value]
    )
    added = _poll_until(
        lambda: cp.list_profile_history_records(DomainName=domain, ProfileId=profile_id),
        lambda r: any(x["ActionType"] == "ADDED_PROFILE_KEY" for x in r.get("ProfileHistoryRecords", [])),
        timeout_s=60,
    )
    added_count = sum(1 for r in added["ProfileHistoryRecords"] if r["ActionType"] == "ADDED_PROFILE_KEY")
    assert added_count == 1, f"expected exactly 1 ADDED_PROFILE_KEY record, got {added_count}"

    found = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_ctrContactId", Values=[contact_value]),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    found_ids = {i["ProfileId"] for i in found["Items"]}
    assert profile_id in found_ids, f"expected {profile_id} searchable by added key, got {found_ids}"

    cp.delete_profile_key(
        DomainName=domain, ProfileId=profile_id, KeyName="_ctrContactId", Values=[contact_value]
    )
    deleted = _poll_until(
        lambda: cp.list_profile_history_records(DomainName=domain, ProfileId=profile_id),
        lambda r: any(x["ActionType"] == "DELETED_PROFILE_KEY" for x in r.get("ProfileHistoryRecords", [])),
        timeout_s=60,
    )
    added_count_after = sum(
        1 for r in deleted["ProfileHistoryRecords"] if r["ActionType"] == "ADDED_PROFILE_KEY"
    )
    deleted_count = sum(
        1 for r in deleted["ProfileHistoryRecords"] if r["ActionType"] == "DELETED_PROFILE_KEY"
    )
    assert added_count_after == 1 and deleted_count == 1, (
        f"expected the ADDED_PROFILE_KEY record retained and exactly 1 DELETED_PROFILE_KEY record, "
        f"got added={added_count_after} deleted={deleted_count}"
    )

    gone = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_ctrContactId", Values=[contact_value]),
        lambda r: len(r.get("Items", [])) == 0,
        timeout_s=60,
    )
    assert gone.get("Items", []) == [], (
        f"expected key no longer searchable after delete, got {gone.get('Items')}"
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
