"""create-profile-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-profile-lifecycle"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfile provisions a Profile that settles into COMPLETE with NOT_SHARED share status."""
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    profile = _create_profile(ctx, name)
    profile_id = profile["Id"]
    ctx.on_cleanup(lambda: r53p.delete_profile(ProfileId=profile_id))

    assert profile["Name"] == name, f"expected Name {name!r}, got {profile['Name']!r}"
    assert profile["ShareStatus"] == "NOT_SHARED", (
        f"expected ShareStatus NOT_SHARED, got {profile['ShareStatus']!r}"
    )
    assert profile["Status"] in ("CREATING", "COMPLETE"), (
        f"unexpected initial Status {profile['Status']!r}"
    )

    status = _poll_until(
        probe=lambda: r53p.get_profile(ProfileId=profile_id)["Profile"]["Status"],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert status == "COMPLETE", f"profile settled into {status!r} instead of COMPLETE"

    fetched = r53p.get_profile(ProfileId=profile_id)["Profile"]
    assert fetched["Id"] == profile_id, f"expected Id {profile_id!r}, got {fetched['Id']!r}"
    assert fetched["Name"] == name, f"expected Name {name!r}, got {fetched['Name']!r}"
    assert fetched["Arn"].endswith(profile_id), (
        f"expected Arn to end with {profile_id!r}, got {fetched['Arn']!r}"
    )


def _create_profile(ctx, name: str) -> dict:
    r53p = ctx.client("route53profiles")
    deadline = time.monotonic() + min(400, ctx.time_left() or 400)
    while True:
        try:
            return r53p.create_profile(
                Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-")
            )["Profile"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
