"""lookup-events-invalid-time-range-fails."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises, because an emulator accepting input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


CHECK = "lookup-events-invalid-time-range-fails"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents rejects a StartTime that is after EndTime; a validly-ordered window is
    accepted, so the rejection is shown to be specific to the ordering rather than to the
    operation or the account as a whole."""
    ct = ctx.client("cloudtrail")

    now = datetime.datetime.now(datetime.timezone.utc)

    # Positive control: a validly-ordered window succeeds.
    response = ct.lookup_events(StartTime=now - datetime.timedelta(days=1), EndTime=now)
    assert "Events" in response, f"expected an Events key on a successful call, got {response!r}"

    code, message = _error(
        lambda: ct.lookup_events(
            StartTime=now, EndTime=now - datetime.timedelta(days=1)
        )
    )
    assert code == "InvalidTimeRangeException", (
        f"expected InvalidTimeRangeException for StartTime after EndTime, got {code!r}"
    )
    assert message == "The start time precedes the end time.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
