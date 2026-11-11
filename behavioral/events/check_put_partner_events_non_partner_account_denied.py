"""put-partner-events-non-partner-account-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-partner-events-non-partner-account-denied"
GROUP = "overly-permissive"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutPartnerEvents from a non-partner account fails the well-formed partner entry per entry
    (ErrorCode, no EventId), creates no event source, and PutEvents to the default bus still works.
    """
    events = ctx.client("events")

    partner_segment = ctx.unique_name("sim2real-behav-partner-")
    source_name = f"aws.partner/{partner_segment}/testnamespace/testevent"

    put_res = events.put_partner_events(
        Entries=[
            {
                "Source": source_name,
                "DetailType": "sim2real-test",
                "Detail": "{}",
            }
        ]
    )
    entry = put_res["Entries"][0]
    diag = f"failed={put_res.get('FailedEntryCount')} entry={entry}"
    assert put_res.get("FailedEntryCount") == 1, diag
    assert "EventId" not in entry, diag
    assert entry.get("ErrorCode"), diag

    # Effect absent: the rejected call must not have caused this name to become a describable
    # partner event source shared with the account.
    describe_err = _client_error(lambda: events.describe_event_source(Name=source_name))
    assert describe_err.get("Code") == "ResourceNotFoundException", (
        f"expected the never-created partner source to 404, got {describe_err}"
    )
    expected_message = f"Event source {source_name} does not exist."
    assert describe_err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {describe_err.get('Message')!r}"
    )

    # Positive control: the exact same credentials can still PutEvents to the account's own
    # default bus -- this is a targeted partner-authorization rejection, not a broken client or
    # a blanket deny.
    put_result = events.put_events(
        Entries=[
            {
                "Source": "sim2real.behavioral.control",
                "DetailType": "sim2real-control",
                "Detail": "{}",
            }
        ]
    )
    control_entry = put_result["Entries"][0]
    assert put_result["FailedEntryCount"] == 0, (
        f"expected the positive control PutEvents to the account's own default bus to succeed "
        f"with the same credentials, got FailedEntryCount={put_result.get('FailedEntryCount')} "
        f"entry={control_entry}"
    )
    assert "EventId" in control_entry, (
        f"expected the positive control entry to carry an EventId, got entry={control_entry}"
    )


def _client_error(fn):
    """Botocore Error dict of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
