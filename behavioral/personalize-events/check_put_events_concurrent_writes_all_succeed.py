"""put-events-concurrent-writes-all-succeed."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "put-events-concurrent-writes-all-succeed"
GROUP = "concurrency"
SERVICES = ["personalize-events"]

_INTERACTIONS_FIELDS = [
    {"name": "USER_ID", "type": "string"},
    {"name": "ITEM_ID", "type": "string"},
    {"name": "EVENT_TYPE", "type": "string"},
    {"name": "TIMESTAMP", "type": "long"},
]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutEvents calls writing distinct events to one session on an ACTIVE event tracker all
    return HTTP 200."""
    tracking_id = _create_event_tracker(ctx, _create_dataset_group(ctx))
    pe = ctx.client("personalize-events")
    session_id = ctx.unique_name("sim2real-pevt-sess-")
    racer_count = 20

    def _put(i: int):
        return pe.put_events(
            trackingId=tracking_id,
            sessionId=session_id,
            eventList=[
                {
                    "eventId": f"race-{i}",
                    "eventType": "click",
                    "itemId": f"item-{i}",
                    "sentAt": datetime.now(timezone.utc),
                }
            ],
        )["ResponseMetadata"]["HTTPStatusCode"]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_put, i) for i in range(racer_count)]
        status_codes = [f.result() for f in as_completed(futures)]

    assert len(status_codes) == racer_count, (
        f"expected {racer_count} PutEvents responses, got {len(status_codes)}"
    )
    bad = [code for code in status_codes if code != 200]
    assert not bad, f"expected all {racer_count} concurrent PutEvents calls to return 200, got {bad}"


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
    a full-suite run. Never deleted by an individual check; it is shared by the suite's checks."""
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


def _find_arn_by_name(list_fn, items_key, name, arn_key, **kwargs):
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = list_fn(**call_kwargs)
        for item in resp.get(items_key, []):
            if item.get("name") == name:
                return item[arn_key]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _find_dataset_arn_by_type(personalize, dataset_group_arn, dataset_type):
    next_token = None
    while True:
        kwargs = {"datasetGroupArn": dataset_group_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = personalize.list_datasets(**kwargs)
        for ds in resp.get("datasets", []):
            if ds.get("datasetType") == dataset_type and ds.get("status") == "ACTIVE":
                return ds["datasetArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _ensure_interactions_dataset(ctx, dataset_group_arn):
    """CreateEventTracker requires the dataset group to already own an ACTIVE Interactions
    dataset -- real AWS rejects it with ResourceNotFoundException ("Missing INTERACTIONS
    dataset with datasetgroup") otherwise. Finds-or-creates the ONE shared Interactions dataset/schema, since
    a custom dataset group allows only one dataset per type. Never deleted by an individual
    check; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_arn_by_type(personalize, dataset_group_arn, "Interactions")
    if arn is not None:
        return arn
    schema_name = "sim2real-pevt-schema-shared-interactions"
    ds_name = "sim2real-pevt-ds-shared-interactions"
    schema_arn = _find_arn_by_name(personalize.list_schemas, "schemas", schema_name, "schemaArn")
    if schema_arn is None:
        schema = {
            "type": "record",
            "name": "Interactions",
            "namespace": "com.amazonaws.personalize.schema",
            "fields": _INTERACTIONS_FIELDS,
            "version": "1.0",
        }
        try:
            schema_arn = personalize.create_schema(name=schema_name, schema=json.dumps(schema))["schemaArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            schema_arn = _find_arn_by_name(personalize.list_schemas, "schemas", schema_name, "schemaArn")
    try:
        arn = personalize.create_dataset(
            name=ds_name,
            datasetGroupArn=dataset_group_arn,
            datasetType="Interactions",
            schemaArn=schema_arn,
        )["datasetArn"]
    except personalize.exceptions.ResourceAlreadyExistsException:
        arn = _find_arn_by_name(
            personalize.list_datasets, "datasets", ds_name, "datasetArn",
            datasetGroupArn=dataset_group_arn,
        )
    _poll_until(
        lambda: personalize.describe_dataset(datasetArn=arn)["dataset"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    return arn


def _create_event_tracker(ctx, dataset_group_arn):
    """Finds-or-creates the ONE event tracker for the shared dataset group. Adopts ANY existing
    ACTIVE tracker (not just by exact name) since a dataset group can only ever have one
    Interactions dataset/tracker anyway. Never deleted by an individual check; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    _ensure_interactions_dataset(ctx, dataset_group_arn)
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
