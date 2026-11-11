"""put-action-interactions-reserved-property-keyword-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-action-interactions-reserved-property-keyword-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-events"]

_ACTION_INTERACTIONS_FIELDS = [
    {"name": "USER_ID", "type": "string"},
    {"name": "ACTION_ID", "type": "string"},
    {"name": "EVENT_TYPE", "type": "string"},
    {"name": "TIMESTAMP", "type": "long"},
]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutActionInteractions rejects an action interaction whose properties JSON blob uses a
    reserved keyword ("sessionId") as a key with InvalidInputException, leaving the well-formed
    sibling call (same tracker/session, non-reserved key) to succeed as a positive control."""
    dataset_group_arn = _create_dataset_group(ctx)
    tracking_id = _create_action_interactions_tracker(ctx, dataset_group_arn)
    pe = ctx.client("personalize-events")
    session_id = ctx.unique_name("sim2real-pevt-sess-")

    def _bad_call():
        pe.put_action_interactions(
            trackingId=tracking_id,
            actionInteractions=[
                {
                    "actionId": "action-1",
                    "sessionId": session_id,
                    "timestamp": int(time.time()),
                    "eventType": "Viewed",
                    "properties": json.dumps({"sessionId": "reserved-collision"}),
                }
            ],
        )

    code = _error_code(_bad_call)
    assert code == "InvalidInputException", (
        f"a PutActionInteractions properties blob using the reserved key 'sessionId' was not "
        f"rejected with InvalidInputException, got {code!r}"
    )

    resp = pe.put_action_interactions(
        trackingId=tracking_id,
        actionInteractions=[
            {
                "actionId": "action-1",
                "sessionId": session_id,
                "timestamp": int(time.time()),
                "eventType": "Viewed",
                "properties": json.dumps({"numberOfActions": "3"}),
            }
        ],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the positive control (identical call, non-reserved key) did not succeed: {resp!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


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


def _find_arn(list_fn, items_key, name, arn_key, **kwargs):
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


def _create_action_interactions_tracker(ctx, dataset_group_arn):
    """Finds-or-creates the Action_Interactions dataset (which auto-provisions its own
    trackingId -- there is no separate CreateEventTracker call for this dataset type) inside
    the shared dataset group. Adopts ANY existing ACTIVE dataset of this TYPE (not just by
    name) -- a custom dataset group allows only one dataset per type, so a stray same-typed
    dataset left over from a prior run is reused rather than fighting it for the slot. Never
    deleted by an individual check; the account-level sweep removes it once, suite-wide."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_arn_by_type(personalize, dataset_group_arn, "Action_Interactions")
    if arn is None:
        ds_name = "sim2real-pevt-ds-shared-action-interactions"
        schema_name = "sim2real-pevt-schema-shared-action-interactions"
        schema_arn = _find_arn(personalize.list_schemas, "schemas", schema_name, "schemaArn")
        if schema_arn is None:
            schema = {
                "type": "record",
                "name": "ActionInteractions",
                "namespace": "com.amazonaws.personalize.schema",
                "fields": _ACTION_INTERACTIONS_FIELDS,
                "version": "1.0",
            }
            try:
                schema_arn = personalize.create_schema(
                    name=schema_name, schema=json.dumps(schema)
                )["schemaArn"]
            except personalize.exceptions.ResourceAlreadyExistsException:
                schema_arn = _find_arn(personalize.list_schemas, "schemas", schema_name, "schemaArn")
        try:
            arn = personalize.create_dataset(
                name=ds_name,
                datasetGroupArn=dataset_group_arn,
                datasetType="Action_Interactions",
                schemaArn=schema_arn,
            )["datasetArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_arn(
                personalize.list_datasets, "datasets", ds_name, "datasetArn",
                datasetGroupArn=dataset_group_arn,
            )
    dataset = _poll_until(
        lambda: personalize.describe_dataset(datasetArn=arn)["dataset"],
        lambda d: d["status"] == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    return dataset["trackingId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
