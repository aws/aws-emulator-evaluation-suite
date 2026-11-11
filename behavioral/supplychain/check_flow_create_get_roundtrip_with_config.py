"""flow-create-get-roundtrip-with-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-create-get-roundtrip-with-config"
GROUP = "control-plane"
SERVICES = ["supplychain"]

# AWS Supply Chain (service prefix "scn") is not available in every region; real AWS rejects
# CreateInstance in us-west-2 with ValidationException "Amazon Connect Decisions is not supported
# in us-west-2". us-east-1 is where the service launched and remains supported.
_SC_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataIntegrationFlow's returned source/target/transformation configuration
    matches what GetDataIntegrationFlow (and ListDataIntegrationFlows) report back."""
    sc = ctx.client("supplychain", region=_SC_REGION)
    instance_id = _create_active_instance(ctx, sc)
    flow_name = ctx.unique_name("sim2real-sc-flow-")
    # AWS Supply Chain provisions a managed S3 bucket per instance as part of CreateInstance's
    # "creating all required Amazon Web Services resources" step, named "aws-supply-chain-data-
    # <instanceId>" (see CreateDataIntegrationFlow's own request example in the Smithy model).
    # A DataIntegrationFlow S3 source must point into that bucket -- any other bucket name is
    # rejected with AccessDeniedException ("not located in a bucket associated with the ASC
    # instance").
    bucket = f"aws-supply-chain-data-{instance_id}"

    # An S3 *target* is categorically rejected by real AWS: "Authorization Failed. Creating a
    # flow with s3 as target is not allowed through public API."
    # The target is a DATASET instead, matching the Smithy model's own "s3 to dataset flow"
    # example -- a real dataset in a fresh custom namespace, created for this check.
    namespace_name = ctx.unique_name("sim2real_sc_ns_")
    dataset_name = ctx.unique_name("sim2real_sc_ds_")
    sc.create_data_lake_namespace(instanceId=instance_id, name=namespace_name)
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_namespace(instanceId=instance_id, name=namespace_name)
        )
    )
    dataset = sc.create_data_lake_dataset(
        instanceId=instance_id,
        namespace=namespace_name,
        name=dataset_name,
        schema={
            "name": "SimParitySchema",
            "fields": [{"name": "id", "type": "STRING", "isRequired": False}],
        },
    )["dataset"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sc.delete_data_lake_dataset(instanceId=instance_id, namespace=namespace_name, name=dataset_name)
        )
    )
    dataset_arn = dataset["arn"]

    sources = [
        {"sourceType": "S3", "sourceName": "src", "s3Source": {"bucketName": bucket, "prefix": "in/"}}
    ]
    transformation = {
        "transformationType": "SQL",
        "sqlTransformation": {"query": "SELECT * FROM src"},
    }
    target = {"targetType": "DATASET", "datasetTarget": {"datasetIdentifier": dataset_arn}}

    created = sc.create_data_integration_flow(
        instanceId=instance_id,
        name=flow_name,
        sources=sources,
        transformation=transformation,
        target=target,
        tags={"team": "sim2real"},
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sc.delete_data_integration_flow(instanceId=instance_id, name=flow_name))
    )
    assert created["name"] == flow_name, f"expected created flow name {flow_name!r}, got {created['name']!r}"

    fetched = sc.get_data_integration_flow(instanceId=instance_id, name=flow_name)["flow"]
    assert fetched["sources"][0]["sourceName"] == "src", (
        f"expected source name 'src', got {fetched['sources'][0].get('sourceName')!r}"
    )
    assert fetched["sources"][0]["s3Source"]["bucketName"] == bucket, (
        f"expected source bucket {bucket!r}, got {fetched['sources'][0]['s3Source'].get('bucketName')!r}"
    )
    assert fetched["transformation"]["transformationType"] == "SQL", (
        f"expected transformation type 'SQL', got {fetched['transformation'].get('transformationType')!r}"
    )
    assert fetched["transformation"]["sqlTransformation"]["query"] == "SELECT * FROM src", (
        f"expected SQL query 'SELECT * FROM src', got "
        f"{fetched['transformation'].get('sqlTransformation', {}).get('query')!r}"
    )
    assert fetched["target"]["targetType"] == "DATASET", (
        f"expected target type 'DATASET', got {fetched['target'].get('targetType')!r}"
    )
    assert fetched["target"]["datasetTarget"]["datasetIdentifier"] == dataset_arn, (
        f"expected target dataset {dataset_arn!r}, got "
        f"{fetched['target'].get('datasetTarget', {}).get('datasetIdentifier')!r}"
    )

    names = {f["name"] for f in sc.list_data_integration_flows(instanceId=instance_id)["flows"]}
    assert flow_name in names, f"{flow_name} not found in flow list: {names}"


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
        tags={"team": "sim2real"},
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
