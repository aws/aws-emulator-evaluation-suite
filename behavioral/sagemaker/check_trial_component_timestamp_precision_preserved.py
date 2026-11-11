"""trial-component-timestamp-precision-preserved."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-component-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Trial component StartTime and EndTime given with microsecond 777777 are stored rounded to
    the millisecond (778000); after delete, DescribeTrialComponent and UpdateTrialComponent are
    refused with ResourceNotFound and the exact message.
    """
    sm = ctx.client("sagemaker")

    start_time = datetime(2024, 3, 15, 12, 0, 0, 123456, tzinfo=timezone.utc)
    end_time = start_time + timedelta(seconds=5, microseconds=654321)
    expected_start = _round_to_millisecond(start_time)
    expected_end = _round_to_millisecond(end_time)

    name = ctx.unique_name("sim2real-tc-")
    tc_arn = sm.create_trial_component(
        TrialComponentName=name,
        StartTime=start_time,
        EndTime=end_time,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TrialComponentArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_trial_component(TrialComponentName=name)))

    described = sm.describe_trial_component(TrialComponentName=name)
    got_start = described["StartTime"]
    got_end = described["EndTime"]

    # The real service rounds the supplied value to the nearest millisecond; it does not
    # preserve the sub-millisecond remainder (an emulator that does would be over-precise)
    # and it does not zero the whole sub-second component either (an emulator that
    # truncates to whole seconds would be under-precise).
    assert got_start == expected_start, (
        f"StartTime not rounded to millisecond precision: got {got_start!r}, "
        f"expected {expected_start!r} (supplied {start_time!r})"
    )
    assert got_end == expected_end, (
        f"EndTime not rounded to millisecond precision: got {got_end!r}, "
        f"expected {expected_end!r} (supplied {end_time!r})"
    )

    # Free negative from the teardown this check already performs: deleting the trial
    # component makes it independently unreadable by the specific not-found code, and a
    # mutation against the deleted id is rejected the same way. DescribeTrialComponent
    # is backed by a search index that lags the delete, so this is a bounded retry
    # (the read can still succeed for a couple of seconds after DeleteTrialComponent
    # returns), not an immediate assertion.
    sm.delete_trial_component(TrialComponentName=name)
    expected_message = f"Trial component '{tc_arn}' does not exist."
    describe_code, describe_message = _poll_for_error(
        lambda: sm.describe_trial_component(TrialComponentName=name),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert describe_code == "ResourceNotFound", (
        f"deleted trial component did not 404 within 30s, last saw {describe_code!r}"
    )
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )
    mutate_code, mutate_message = _poll_for_error(
        lambda: sm.update_trial_component(TrialComponentName=name, DisplayName="post-delete"),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert mutate_code == "ResourceNotFound", (
        f"mutation on a deleted trial component did not 404 within 30s, last saw {mutate_code!r}"
    )
    assert mutate_message == expected_message, (
        f"expected message {expected_message!r}, got {mutate_message!r}"
    )


def _round_to_millisecond(dt: datetime) -> datetime:
    whole_second = dt.replace(microsecond=0)
    return whole_second + timedelta(milliseconds=round(dt.microsecond / 1000))


_SUCCEEDED = "<call succeeded>"


def _poll_for_error(fn, *, timeout_s: float, interval_s: float) -> tuple[str, str | None]:
    """Retry fn() until it raises ResourceNotFound; return the last (code, message). A call
    that keeps succeeding returns (_SUCCEEDED, None), a code no AWS error can equal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            last = (_SUCCEEDED, None)
        except ClientError as err:
            last = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
            if last[0] == "ResourceNotFound":
                return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
