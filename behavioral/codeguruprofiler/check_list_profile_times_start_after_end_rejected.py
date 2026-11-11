"""list-profile-times-start-after-end-rejected."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-profile-times-start-after-end-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListProfileTimes rejects a time range where startTime is after endTime with
    ValidationException, and a validly-ordered range (even with no profile data
    yet) still succeeds and returns an empty list rather than an error."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-times-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags={"env": "sim2real"}
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    # a fixed millisecond part keeps the echoed timestamps exact in the message
    now = datetime.now(timezone.utc).replace(microsecond=123000)
    earlier = now - timedelta(hours=1)
    later = now + timedelta(hours=1)

    err = _error(
        lambda: cgp.list_profile_times(
            profilingGroupName=name,
            startTime=later,
            endTime=earlier,
            period="PT5M",
        )
    )
    assert err["Code"] == "ValidationException", (
        f"a startTime after endTime was rejected with {err['Code']!r}, expected "
        f'"ValidationException"'
    )
    expected = (
        f"Interval start time ({later:%Y-%m-%dT%H:%M:%S}.123Z) must be before "
        f"end time ({earlier:%Y-%m-%dT%H:%M:%S}.123Z)"
    )
    assert err["Message"] == expected, (
        f"a startTime after endTime was rejected with message {err['Message']!r}, "
        f"expected {expected!r}"
    )

    # positive control: correctly-ordered range succeeds (empty result is valid,
    # since there is no profile data for this fresh group yet)
    ok = cgp.list_profile_times(
        profilingGroupName=name,
        startTime=earlier,
        endTime=now,
        period="PT5M",
    )
    assert ok["profileTimes"] == [], (
        f'a validly-ordered range on a fresh group returned {ok["profileTimes"]!r}, '
        f"expected an empty list"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
