"""put-events-nonexistent-bus-silently-dropped."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-nonexistent-bus-silently-dropped"
GROUP = 'put-events'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents to a non-existent EventBusName returns HTTP success and an
    EventId per entry rather than a resource-not-found failure; the event
    is simply not routable anywhere."""
    ev = ctx.client("events")
    bogus_bus = ctx.unique_name("sim2real-behav-evb-no-such-bus-")
    resp = ev.put_events(
        Entries=[
            {
                "Source": ctx.unique_name("sim2real.behav.evb.source."),
                "DetailType": "BehavioralCheck",
                "Detail": json.dumps({"x": 1}),
                "EventBusName": bogus_bus,
            }
        ]
    )
    assert resp.get("FailedEntryCount", 0) == 0, (
        f"expected no failures for nonexistent-bus entry, got {resp}"
    )
    assert "EventId" in resp["Entries"][0], f"expected EventId even though bus does not exist: {resp}"

    # Independent read at the destination: PutEvents must not have implicitly
    # created the bus it just accepted an entry for. If it had, "not routable
    # anywhere" would be false — there would now be a bus to route to.
    try:
        ev.describe_event_bus(Name=bogus_bus)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        message = e.response.get("Error", {}).get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException describing a bus that was never "
            f"created, got {code}: {e}"
        )
        expected_message = f"Event bus {bogus_bus} does not exist."
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"describe_event_bus succeeded for {bogus_bus} — PutEvents apparently "
            f"created the bus it was told did not exist"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
