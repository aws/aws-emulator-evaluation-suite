"""tracker-consumer-association-scopes-list-tracker-consumers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tracker-consumer-association-scopes-list-tracker-consumers"
GROUP = 'tracking'
SERVICES = ['location']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """ListTrackerConsumers reflects exactly the consumers currently associated: it
    grows on associate and shrinks on disassociate, never more or less.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_ListTrackerConsumers.html
    """
    loc = ctx.client("location")
    tracker = ctx.unique_name("sim2real-behav-location-tracker-")
    consumer_a = ctx.unique_name("sim2real-behav-location-consumer-a-")
    consumer_b = ctx.unique_name("sim2real-behav-location-consumer-b-")

    loc.create_tracker(TrackerName=tracker)
    ctx.on_cleanup(_teardown(lambda: loc.delete_tracker(TrackerName=tracker), "ResourceNotFoundException"))
    arn_a = loc.create_geofence_collection(CollectionName=consumer_a)["CollectionArn"]
    ctx.on_cleanup(_teardown(lambda: loc.delete_geofence_collection(CollectionName=consumer_a),
                              "ResourceNotFoundException"))
    arn_b = loc.create_geofence_collection(CollectionName=consumer_b)["CollectionArn"]
    ctx.on_cleanup(_teardown(lambda: loc.delete_geofence_collection(CollectionName=consumer_b),
                              "ResourceNotFoundException"))

    def consumers() -> set[str]:
        return set(loc.get_paginator("list_tracker_consumers").paginate(
            TrackerName=tracker).build_full_result()["ConsumerArns"])

    assert consumers() == set(), f"expected no consumers before association, got {consumers()!r}"

    loc.associate_tracker_consumer(TrackerName=tracker, ConsumerArn=arn_a)
    assert consumers() == {arn_a}, f"expected only {arn_a!r} after one association, got {consumers()!r}"

    loc.associate_tracker_consumer(TrackerName=tracker, ConsumerArn=arn_b)
    assert consumers() == {arn_a, arn_b}, f"expected both consumers, got {consumers()!r}"

    loc.disassociate_tracker_consumer(TrackerName=tracker, ConsumerArn=arn_a)
    assert consumers() == {arn_b}, f"expected only {arn_b!r} after disassociating {arn_a!r}, got {consumers()!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
