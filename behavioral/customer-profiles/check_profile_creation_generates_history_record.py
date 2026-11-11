"""profile-creation-generates-history-record."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "profile-creation-generates-history-record"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateProfile writes an audit ProfileHistoryRecord with ActionType CREATED, visible via
    ListProfileHistoryRecords; a profile id that was never created carries no such record."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    fake_profile_id = uuid.uuid4().hex
    try:
        bogus = cp.list_profile_history_records(DomainName=domain, ProfileId=fake_profile_id)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException listing history for a profile id that was "
            f"never created, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == f"Profile {fake_profile_id} not found in domain {domain}", (
            f"unexpected message listing history for a never-created profile id: {message!r}"
        )
    else:
        bogus_records = bogus.get("ProfileHistoryRecords", [])
        assert bogus_records == [], (
            f"expected no history records for a profile id that was never created, "
            f"got {bogus_records!r}"
        )

    profile_id = cp.create_profile(DomainName=domain, FirstName="Jane")["ProfileId"]

    records = _poll_until(
        lambda: cp.list_profile_history_records(DomainName=domain, ProfileId=profile_id),
        lambda r: len(r.get("ProfileHistoryRecords", [])) > 0,
        timeout_s=60,
    )
    action_types = {r["ActionType"] for r in records["ProfileHistoryRecords"]}
    assert "CREATED" in action_types, (
        f"expected a CREATED history record after CreateProfile for profile {profile_id}, "
        f"got action types {action_types!r}"
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
