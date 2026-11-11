"""dataset-create-get-list-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dataset-create-get-list-roundtrip"
GROUP = "control-plane"
SERVICES = ["supplychain"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataLakeDataset's returned schema matches GetDataLakeDataset and the dataset
    appears in ListDataLakeDatasets for its namespace."""
    sc = ctx.client("supplychain", region="us-east-1")  # AWS Supply Chain is not available in us-west-2
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _create_namespace(ctx, sc, instance_id)
    ds_name = _dl_name(ctx, "ds")

    schema = {
        "name": "SimTwoRealSchema",
        "fields": [
            {"name": "id", "type": "STRING", "isRequired": True},
            {"name": "value", "type": "STRING", "isRequired": False},
        ],
        "primaryKeys": [{"name": "id"}],
    }
    created = sc.create_data_lake_dataset(
        instanceId=instance_id,
        namespace=ns_name,
        name=ds_name,
        schema=schema,
        tags={"sim2real": "true"},
    )["dataset"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)
        )
    )

    assert created["name"] == ds_name, f"expected name {ds_name!r}, got {created['name']!r}"
    assert created["schema"]["fields"] == schema["fields"], (
        f"expected fields {schema['fields']!r}, got {created['schema']['fields']!r}"
    )
    assert created["schema"]["primaryKeys"] == schema["primaryKeys"], (
        f"expected primaryKeys {schema['primaryKeys']!r}, got {created['schema']['primaryKeys']!r}"
    )

    fetched = sc.get_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)["dataset"]
    assert fetched["arn"] == created["arn"], f"expected arn {created['arn']!r}, got {fetched['arn']!r}"
    assert fetched["schema"]["name"] == "SimTwoRealSchema", (
        f"expected schema name 'SimTwoRealSchema', got {fetched['schema']['name']!r}"
    )
    assert fetched["schema"]["fields"] == schema["fields"], (
        f"independent read diverged from create response: expected fields {schema['fields']!r}, "
        f"got {fetched['schema']['fields']!r}"
    )
    assert fetched["schema"]["primaryKeys"] == schema["primaryKeys"], (
        f"independent read diverged from create response: expected primaryKeys {schema['primaryKeys']!r}, "
        f"got {fetched['schema']['primaryKeys']!r}"
    )

    names = {d["name"] for d in sc.list_data_lake_datasets(instanceId=instance_id, namespace=ns_name)["datasets"]}
    assert ds_name in names, f"{ds_name} not found in dataset list: {names}"


def _dl_name(ctx, kind):
    """Sanitize ctx.unique_name output to satisfy the ^[a-z0-9_]+$ data-lake naming pattern."""
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"sim2real": "true"},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


def _create_namespace(ctx, sc, instance_id):
    ns_name = _dl_name(ctx, "ns")
    sc.create_data_lake_namespace(
        instanceId=instance_id,
        name=ns_name,
        description="sim2real namespace",
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    )
    return ns_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
