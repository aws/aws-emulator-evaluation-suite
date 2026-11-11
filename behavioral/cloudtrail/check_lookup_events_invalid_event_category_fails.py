"""lookup-events-invalid-event-category-fails."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected LookupEvents to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "lookup-events-invalid-event-category-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """LookupEvents enforces the EventCategory enum ('insight') instead of ignoring unknown values."""
    ct = ctx.client("cloudtrail")

    # Positive control: an otherwise-plain LookupEvents call must succeed, so the rejection below
    # is provably about the bogus EventCategory and not about a broken account/credentials.
    ct.lookup_events(MaxResults=1)

    code, message = _error(
        lambda: ct.lookup_events(EventCategory="sim2real-behav-bogus-category")
    )
    assert code == "InvalidEventCategoryException", code
    assert message == "Invalid event category specified.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
