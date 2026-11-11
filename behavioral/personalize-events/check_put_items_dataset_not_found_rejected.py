"""put-items-dataset-not-found-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-items-dataset-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-events"]

_ITEMS_FIELDS = [
    {"name": "ITEM_ID", "type": "string"},
    {"name": "PRICE", "type": ["null", "float"]},
]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItems on a well-formed datasetArn of a never-created dataset group gets InvalidInputException
    "Invalid datasetArn", while the same call on the ACTIVE Items dataset returns HTTP 200."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_dataset(
        ctx, dataset_group_arn, "Items", "Items", _ITEMS_FIELDS, "items"
    )
    pe = ctx.client("personalize-events")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:personalize:{ctx.region}:{account_id}:dataset/"
        f"{ctx.unique_name('sim2real-pevt-dsg-nope-')}/Items"
    )

    def _bad_call():
        pe.put_items(
            datasetArn=bogus_arn,
            items=[{"itemId": "item-1", "properties": json.dumps({"price": 9.99})}],
        )

    err = _error(_bad_call)
    assert err["Code"] == "InvalidInputException", f"expected InvalidInputException, got {err!r}"
    assert err["Message"] == "Invalid datasetArn", f"unexpected unknown-dataset message {err['Message']!r}"

    resp = pe.put_items(
        datasetArn=dataset_arn,
        items=[{"itemId": "item-1", "properties": json.dumps({"price": 9.99})}],
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 against the real, ACTIVE Items dataset, got {status!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict ({"Code", "Message", ...}). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    """Finds-or-creates the ONE shared custom dataset group reused by the whole suite (a
    custom dataset group holds one dataset of each type -- Interactions, Items, Users, Actions,
    Action_Interactions -- so every check fits in it), instead of each check minting its own,
    which blows the account's 5-active-dataset-group quota under a full-suite run. Never
    deleted by an individual check; it is shared by the suite's checks."""
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


def _create_dataset(ctx, dataset_group_arn, dataset_type, record_name, fields, name_prefix):
    """Finds-or-creates the shared <dataset_type> dataset (and its schema) inside the shared
    dataset group. Adopts ANY existing ACTIVE dataset of this TYPE in the group (not just by
    name) -- a custom dataset group allows only one dataset per type, so a stray same-typed
    dataset left over from a prior run is reused rather than fighting it for the slot. Never
    deleted by an individual check; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_arn_by_type(personalize, dataset_group_arn, dataset_type)
    if arn is None:
        ds_name = f"sim2real-pevt-ds-shared-{name_prefix}"
        schema_name = f"sim2real-pevt-schema-shared-{name_prefix}"
        schema_arn = _find_arn(personalize.list_schemas, "schemas", schema_name, "schemaArn")
        if schema_arn is None:
            schema = {
                "type": "record",
                "name": record_name,
                "namespace": "com.amazonaws.personalize.schema",
                "fields": fields,
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
                datasetType=dataset_type,
                schemaArn=schema_arn,
            )["datasetArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_arn(
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
