"""delete-profile-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-profile-lifecycle"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteProfile removes a Profile permanently: it disappears from GetProfile and
    ListProfiles, and a second DeleteProfile on the now-dead id also fails not-found."""
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    profile_id = r53p.create_profile(Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-"))[
        "Profile"
    ]["Id"]
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))

    r53p.delete_profile(ProfileId=profile_id)

    _poll_until(
        probe=lambda: _is_gone(lambda: r53p.get_profile(ProfileId=profile_id)),
        predicate=bool,
        timeout_s=90,
        interval_s=3,
    )
    expected_message = f'[RSLVR-05007] Can\'t find the resource with ID "{profile_id}".'
    error = _client_error(lambda: r53p.get_profile(ProfileId=profile_id))
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error['Code']!r}"
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    listing = r53p.list_profiles()["ProfileSummaries"]
    assert profile_id not in {p["Id"] for p in listing}, (
        f"deleted profile {profile_id} must not still appear in ListProfiles, saw {listing!r}"
    )

    # a mutation on the now-dead id must also fail not-found, not silently no-op
    second_delete = _client_error(lambda: r53p.delete_profile(ProfileId=profile_id))
    assert second_delete["Code"] == "ResourceNotFoundException", (
        f"expected a second DeleteProfile on an already-deleted profile to fail with "
        f"ResourceNotFoundException, got {second_delete['Code']!r}"
    )
    assert second_delete["Message"] == expected_message, (
        f"expected {expected_message!r}, got {second_delete['Message']!r}"
    )


def _client_error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises: a target
    that accepts what real AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _is_gone(fn) -> bool:
    """Poll probe: True once fn() fails not-found, False while it still succeeds."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
