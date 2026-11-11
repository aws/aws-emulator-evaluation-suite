"""create-dataset-duplicate-name-conflict-then-new-name-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-dataset-duplicate-name-conflict-then-new-name-succeeds"
GROUP = "error-semantics"
SERVICES = ["supplychain"]

# AWS Supply Chain is a single-region service, us-east-1 only; ctx.client("supplychain")
# with no pin resolves to ctx.region (often us-west-2) and every call fails.
_SC_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataLakeDataset rejects a second create with the same name/namespace as a
    conflict, leaves the original dataset's description untouched, and a create with a
    different name still succeeds."""
    sc = ctx.client("supplychain", region=_SC_REGION)
    instance_id = _create_active_instance(ctx, sc)
    ns_name = _create_namespace(ctx, sc, instance_id)
    ds_name = _dl_name(ctx, "ds")

    original_schema = {"name": "OriginalSchema", "fields": [{"name": "id", "type": "STRING", "isRequired": True}]}
    sc.create_data_lake_dataset(
        instanceId=instance_id,
        namespace=ns_name,
        name=ds_name,
        schema=original_schema,
        description="original description",
        tags={"team": "sim2real"},
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)
        )
    )

    conflicting_schema = {"name": "ConflictSchema", "fields": [{"name": "other", "type": "STRING", "isRequired": True}]}
    code, message = _error(
        lambda: sc.create_data_lake_dataset(
            instanceId=instance_id,
            namespace=ns_name,
            name=ds_name,
            schema=conflicting_schema,
            description="attempted overwrite",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = f"Dataset {ds_name} already exist in namespace {ns_name}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    unchanged = sc.get_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=ds_name)["dataset"]
    assert unchanged["description"] == "original description", (
        f"expected description to survive the rejected conflicting create unchanged, got {unchanged['description']!r}"
    )
    assert unchanged["schema"]["name"] == "OriginalSchema", (
        f"expected schema to survive the rejected conflicting create unchanged, got {unchanged['schema']['name']!r}"
    )

    other_ds_name = _dl_name(ctx, "ds2")
    sc.create_data_lake_dataset(
        instanceId=instance_id,
        namespace=ns_name,
        name=other_ds_name,
        schema=original_schema,
        tags={"team": "sim2real"},
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=other_ds_name)
        )
    )

    other_read = sc.get_data_lake_dataset(instanceId=instance_id, namespace=ns_name, name=other_ds_name)["dataset"]
    assert other_read["name"] == other_ds_name, (
        f"expected an independent read to find the differently-named dataset {other_ds_name!r}, got {other_read['name']!r}"
    )
    assert other_read["schema"]["name"] == "OriginalSchema", (
        f"expected the differently-named dataset's schema to be OriginalSchema, got {other_read['schema']['name']!r}"
    )


def _dl_name(ctx, kind):
    raw = ctx.unique_name(f"sim2real-sc-{kind}-")
    return raw.lower().replace("-", "").replace(".", "")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        instanceName=name, instanceDescription="sim2real behavioral check", tags={"team": "sim2real"}
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
        instanceId=instance_id, name=ns_name, description="sim2real namespace", tags={"team": "sim2real"}
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=ns_name))
    )
    return ns_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
