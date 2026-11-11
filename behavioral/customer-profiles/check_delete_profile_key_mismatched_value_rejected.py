"""delete-profile-key-mismatched-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-profile-key-mismatched-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["customer-profiles"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteProfileKey with a value that was never added for that key is rejected with ResourceNotFoundException
    (not BadRequestException) and leaves the real key intact."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    real_value = ctx.unique_name("sim2real-contact-real-")
    wrong_value = ctx.unique_name("sim2real-contact-wrong-")

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    profile_id = cp.create_profile(DomainName=domain)["ProfileId"]
    cp.add_profile_key(
        DomainName=domain, ProfileId=profile_id, KeyName="_ctrContactId", Values=[real_value]
    )
    added = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_ctrContactId", Values=[real_value]),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    assert profile_id in {i["ProfileId"] for i in added.get("Items", [])}, (
        f"expected {profile_id!r} searchable by the just-added real value, got {added.get('Items')!r}"
    )

    # wrong_value was never added for _ctrContactId on this profile, so DeleteProfileKey must
    # reject it. The positive control below deletes the value that is present on the same key.
    code, message = _error(
        lambda: cp.delete_profile_key(
            DomainName=domain, ProfileId=profile_id, KeyName="_ctrContactId", Values=[wrong_value]
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a value never added for this key, got {code!r}"
    )
    assert message == "Failed to delete profile key due to key not found", (
        f"unexpected message deleting a value never added for this key: {message!r}"
    )

    # effect absent: the real key value is still searchable (the wrong-value delete did not remove it).
    still_found = cp.search_profiles(
        DomainName=domain, KeyName="_ctrContactId", Values=[real_value]
    )
    assert profile_id in {i["ProfileId"] for i in still_found.get("Items", [])}, (
        f"expected {profile_id!r} still searchable by the real value after the rejected delete, "
        f"got {still_found.get('Items')!r}"
    )

    # positive control: deleting with the correct value succeeds and removes it.
    cp.delete_profile_key(
        DomainName=domain, ProfileId=profile_id, KeyName="_ctrContactId", Values=[real_value]
    )
    removed = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_ctrContactId", Values=[real_value]),
        lambda r: len(r.get("Items", [])) == 0,
        timeout_s=60,
    )
    assert removed.get("Items", []) == [], (
        f"expected no profiles searchable by the real value after deleting it with the matching "
        f"value, got {removed.get('Items')!r}"
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
