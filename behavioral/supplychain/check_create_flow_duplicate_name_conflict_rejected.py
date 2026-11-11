"""create-flow-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-flow-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataIntegrationFlow with an existing name fails with ConflictException and the exact message
    and leaves the original flow's target unchanged, while a flow with a different name is created
    with its own target."""
    # AWS Supply Chain exists only in us-east-1 and eu-west-1 (other regions reject
    # CreateInstance with ValidationException), so the clients pin us-east-1.
    sc = ctx.client("supplychain", region="us-east-1")
    account_id = ctx.client("sts", region="us-east-1").get_caller_identity()["Account"]
    instance_id = _create_active_instance(ctx, sc)
    # CreateInstance provisions this instance's own data-lake bucket (confirmed against real AWS:
    # an S3 source/target outside it is rejected with AccessDeniedException "not located in a
    # bucket associated with the ASC instance"). An S3 SOURCE must be this bucket; an S3 TARGET is
    # separately rejected outright -- "Creating a flow with s3 as target is not allowed through
    # public API" -- so the target must be a dataset instead.
    bucket = f"aws-supply-chain-data-{instance_id}"
    resource_tags = {"team": "sim2real"}

    # Three datasets, not two: a dataset target is exclusively claimed by the flow that first
    # succeeds against it (confirmed against real AWS: ValidationException "Target '<dataset>' is
    # already associated with another flow"), so the different-named flow below needs its OWN
    # target rather than reusing dataset_a's.
    dataset_a = _create_dataset(ctx, sc, instance_id, resource_tags)
    dataset_b = _create_dataset(ctx, sc, instance_id, resource_tags)
    dataset_c = _create_dataset(ctx, sc, instance_id, resource_tags)
    dataset_a_arn = _dataset_arn(account_id, instance_id, dataset_a)
    dataset_b_arn = _dataset_arn(account_id, instance_id, dataset_b)
    dataset_c_arn = _dataset_arn(account_id, instance_id, dataset_c)

    flow_name = ctx.unique_name("sim2real-sc-flow-")
    sources = [
        {"sourceType": "S3", "sourceName": "src", "s3Source": {"bucketName": bucket, "prefix": "in/"}}
    ]
    original_target = {"targetType": "DATASET", "datasetTarget": {"datasetIdentifier": dataset_a_arn}}
    sc.create_data_integration_flow(
        instanceId=instance_id,
        name=flow_name,
        sources=sources,
        transformation={"transformationType": "NONE"},
        target=original_target,
        tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_integration_flow(instanceId=instance_id, name=flow_name))
    )

    other_target = {"targetType": "DATASET", "datasetTarget": {"datasetIdentifier": dataset_b_arn}}
    code, message = _error(
        lambda: sc.create_data_integration_flow(
            instanceId=instance_id,
            name=flow_name,
            sources=sources,
            transformation={"transformationType": "NONE"},
            target=other_target,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = f"Flow with flow name: {flow_name} already exists"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    unchanged = sc.get_data_integration_flow(instanceId=instance_id, name=flow_name)["flow"]
    assert unchanged["target"]["datasetTarget"]["datasetIdentifier"] == dataset_a_arn, (
        "flow config mutated by rejected duplicate create"
    )

    other_flow_name = ctx.unique_name("sim2real-sc-flow2-")
    third_target = {"targetType": "DATASET", "datasetTarget": {"datasetIdentifier": dataset_c_arn}}
    created_other = sc.create_data_integration_flow(
        instanceId=instance_id,
        name=other_flow_name,
        sources=sources,
        transformation={"transformationType": "NONE"},
        target=third_target,
        tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_integration_flow(instanceId=instance_id, name=other_flow_name))
    )
    assert created_other["name"] == other_flow_name, (
        f"create response name mismatch: expected {other_flow_name}, got {created_other.get('name')}"
    )

    other_flow = sc.get_data_integration_flow(instanceId=instance_id, name=other_flow_name)["flow"]
    assert other_flow["target"]["datasetTarget"]["datasetIdentifier"] == dataset_c_arn, (
        f"independent read of the different-named flow shows wrong target: {other_flow['target']}"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _dataset_arn(account_id, instance_id, name, namespace="default"):
    return f"arn:aws:scn:us-east-1:{account_id}:instance/{instance_id}/namespaces/{namespace}/datasets/{name}"


def _create_dataset(ctx, sc, instance_id, resource_tags):
    name = ctx.unique_name("sim2real_sc_ds_").lower().replace("-", "_")
    sc.create_data_lake_dataset(
        instanceId=instance_id,
        namespace="default",
        name=name,
        schema={"name": "Schema", "fields": [{"name": "id", "type": "STRING", "isRequired": True}]},
        tags=resource_tags,
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace="default", name=name)
        )
    )
    return name


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
