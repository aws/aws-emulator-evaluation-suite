"""put-events-optional-fields-round-trip-success."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "put-events-optional-fields-round-trip-success"
GROUP = "data-plane"
SERVICES = ["personalize-events"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents succeeds when every optional Event field is populated: userId, itemId,
    eventValue, a non-reserved properties JSON blob, recommendationId, impression list and
    eventId, on a real ACTIVE event tracker."""
    dataset_group_arn = _create_dataset_group(ctx)
    _create_interactions_dataset(ctx, dataset_group_arn)
    tracking_id = _create_event_tracker(ctx, dataset_group_arn)
    pe = ctx.client("personalize-events")
    event_id = str(uuid.uuid4())
    resp = pe.put_events(
        trackingId=tracking_id,
        sessionId=ctx.unique_name("sim2real-pevt-sess-"),
        userId=ctx.unique_name("sim2real-pevt-user-"),
        eventList=[
            {
                "eventId": event_id,
                "eventType": "watch",
                "eventValue": 4.5,
                "itemId": "movie-42",
                "sentAt": datetime.now(timezone.utc),
                "properties": json.dumps({"numberOfRatings": "12"}),
                "recommendationId": "rec-" + event_id[:32],
                "impression": ["movie-1", "movie-2", "movie-42"],
            }
        ],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert set(resp.keys()) == {"ResponseMetadata"}


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


_SHARED_DSG_NAME = "sim2real-pevt-dsg-shared"
_SHARED_TRACKER_NAME = "sim2real-pevt-trk-shared"


def _find_dataset_group_arn(personalize):
    """Adopts ANY existing ACTIVE dataset group this suite created (name prefix
    "sim2real-pevt-dsg") rather than insisting on one exact name -- a prior run's group that
    didn't get torn down (e.g. an interrupted suite) is reused instead of minting a new one and
    blowing the account's hard 5-active-dataset-group quota."""
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = personalize.list_dataset_groups(**kwargs)
        for g in resp.get("datasetGroups", []):
            if g["name"].startswith("sim2real-pevt-dsg") and g["status"] == "ACTIVE":
                return g["datasetGroupArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_dataset_group(ctx):
    """Finds-or-creates the ONE shared custom dataset group reused by the whole suite instead
    of each check minting its own, which blows the account's 5-active-dataset-group quota under
    a full-suite run. Never deleted by an individual check; the suite-level account sweep tears
    it down once, after every check is done with it."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_group_arn(personalize)
    if arn is None:
        try:
            arn = personalize.create_dataset_group(name=_SHARED_DSG_NAME)["datasetGroupArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_dataset_group_arn(personalize)
    _poll_until(
        lambda: personalize.describe_dataset_group(datasetGroupArn=arn)["datasetGroup"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    return arn


_SHARED_SCHEMA_NAME = "sim2real-pevt-ia-schema-shared"
_SHARED_INTERACTIONS_DATASET_NAME = "sim2real-pevt-ia-ds-shared"
_INTERACTIONS_SCHEMA_JSON = json.dumps(
    {
        "type": "record",
        "name": "Interactions",
        "namespace": "aws.personalize.schema",
        "fields": [
            {"name": "USER_ID", "type": "string"},
            {"name": "ITEM_ID", "type": "string"},
            {"name": "TIMESTAMP", "type": "long"},
        ],
        "version": "1.0",
    }
)


def _find_schema_arn(personalize, name):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = personalize.list_schemas(**kwargs)
        for s in resp.get("schemas", []):
            if s["name"] == name:
                return s["schemaArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _find_interactions_dataset_arn(personalize, dataset_group_arn):
    next_token = None
    while True:
        kwargs = {"datasetGroupArn": dataset_group_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = personalize.list_datasets(**kwargs)
        for d in resp.get("datasets", []):
            if d["datasetType"] == "INTERACTIONS":
                return d["datasetArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_interactions_dataset(ctx, dataset_group_arn):
    """CreateEventTracker requires an existing INTERACTIONS dataset in the dataset group --
    real AWS rejects it with ResourceNotFoundException ("Missing INTERACTIONS dataset")
    otherwise, since PutEvents appends straight into that dataset. Finds-or-creates the ONE
    shared schema and dataset reused by the whole suite; never deleted by an individual check,
    same lifecycle as the shared dataset group and tracker."""
    personalize = ctx.client("personalize")
    arn = _find_interactions_dataset_arn(personalize, dataset_group_arn)
    if arn is None:
        schema_arn = _find_schema_arn(personalize, _SHARED_SCHEMA_NAME)
        if schema_arn is None:
            try:
                schema_arn = personalize.create_schema(
                    name=_SHARED_SCHEMA_NAME, schema=_INTERACTIONS_SCHEMA_JSON
                )["schemaArn"]
            except personalize.exceptions.ResourceAlreadyExistsException:
                schema_arn = _find_schema_arn(personalize, _SHARED_SCHEMA_NAME)
        try:
            arn = personalize.create_dataset(
                name=_SHARED_INTERACTIONS_DATASET_NAME,
                schemaArn=schema_arn,
                datasetGroupArn=dataset_group_arn,
                datasetType="INTERACTIONS",
            )["datasetArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_interactions_dataset_arn(personalize, dataset_group_arn)
    _poll_until(
        lambda: personalize.describe_dataset(datasetArn=arn)["dataset"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    return arn


def _find_first_arn(list_fn, items_key, arn_key, **kwargs):
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = list_fn(**call_kwargs)
        for item in resp.get(items_key, []):
            if item.get("status") == "ACTIVE":
                return item[arn_key]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_event_tracker(ctx, dataset_group_arn):
    """Finds-or-creates the ONE event tracker for the shared dataset group. Adopts ANY existing
    ACTIVE tracker (not just by exact name) since a dataset group can only ever have one
    Interactions dataset/tracker anyway. Never deleted by an individual check; the
    account-level sweep removes it once, suite-wide."""
    personalize = ctx.client("personalize")
    arn = _find_first_arn(
        personalize.list_event_trackers, "eventTrackers", "eventTrackerArn",
        datasetGroupArn=dataset_group_arn,
    )
    if arn is None:
        try:
            arn = personalize.create_event_tracker(
                name=_SHARED_TRACKER_NAME, datasetGroupArn=dataset_group_arn
            )["eventTrackerArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_first_arn(
                personalize.list_event_trackers, "eventTrackers", "eventTrackerArn",
                datasetGroupArn=dataset_group_arn,
            )
    tracker = _poll_until(
        lambda: personalize.describe_event_tracker(eventTrackerArn=arn)["eventTracker"],
        lambda t: t["status"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    return tracker["trackingId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
