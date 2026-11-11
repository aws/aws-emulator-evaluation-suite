"""start-flow-returns-new-execution-id-each-run."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-flow-returns-new-execution-id-each-run"
GROUP = "data-plane"
SERVICES = ["appflow"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two runs of one on-demand flow yield distinct execution ids that each reach Successful and
    both appear in DescribeFlowExecutionRecords.
    """
    s3 = ctx.client("s3")
    appflow = ctx.client("appflow")

    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)
    s3.put_object(Bucket=src_bucket, Key="input/data.csv", Body=b"id,message\n1,run-marker\n")

    flow_name = ctx.unique_name("sim2real-af-flow-")
    appflow.create_flow(
        flowName=flow_name,
        triggerConfig={"triggerType": "OnDemand"},
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=_passthrough_tasks(["id", "message"]),
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=flow_name, forceDelete=True))

    first_id = appflow.start_flow(flowName=flow_name)["executionId"]
    first_record = _wait_for_execution(appflow, flow_name, first_id, {"Successful", "Error"})
    assert first_record["executionStatus"] == "Successful", (
        f"expected first run of {flow_name} to reach Successful, got {first_record['executionStatus']}"
    )

    second_id = appflow.start_flow(flowName=flow_name)["executionId"]
    second_record = _wait_for_execution(appflow, flow_name, second_id, {"Successful", "Error"})
    assert second_record["executionStatus"] == "Successful", (
        f"expected second run of {flow_name} to reach Successful, got {second_record['executionStatus']}"
    )

    assert first_id != second_id, (
        f"expected two StartFlow calls to mint distinct execution ids, both returned {first_id}"
    )
    all_ids = {rec["executionId"] for rec in appflow.describe_flow_execution_records(flowName=flow_name)["flowExecutions"]}
    assert {first_id, second_id} <= all_ids, (
        f"expected DescribeFlowExecutionRecords to list both {first_id} and {second_id}, got {all_ids}"
    )


def _wait_for_execution(appflow, flow_name: str, execution_id: str, targets: set[str], timeout_s: float = 240.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        records = appflow.describe_flow_execution_records(flowName=flow_name)["flowExecutions"]
        for rec in records:
            if rec["executionId"] == execution_id:
                last = rec
                if rec["executionStatus"] in targets:
                    return rec
        time.sleep(5.0)
    raise AssertionError(f"execution {execution_id} of {flow_name} never reached {targets}, last={last}")


def _create_appflow_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-af-{kind}-").lower().replace("_", "-")
    # us-east-1 is S3's original default region and rejects an explicit
    # LocationConstraint for it; every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _put_source_bucket_policy(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAppFlowSourceActions",
            "Effect": "Allow",
            "Principal": {"Service": "appflow.amazonaws.com"},
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _put_destination_bucket_policy(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAppFlowDestinationActions",
            "Effect": "Allow",
            "Principal": {"Service": "appflow.amazonaws.com"},
            "Action": [
                "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
                "s3:ListBucketMultipartUploads", "s3:GetBucketAcl", "s3:PutObjectAcl",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _s3_source_config(bucket: str, prefix: str) -> dict:
    return {
        "connectorType": "S3",
        "sourceConnectorProperties": {
            "S3": {"bucketName": bucket, "bucketPrefix": prefix, "s3InputFormatConfig": {"s3InputFileType": "CSV"}}
        },
    }


def _s3_destination_config(bucket: str, prefix: str) -> dict:
    return {
        "connectorType": "S3",
        "destinationConnectorProperties": {
            "S3": {"bucketName": bucket, "bucketPrefix": prefix, "s3OutputFormatConfig": {"fileType": "JSON"}}
        },
    }


def _passthrough_tasks(fields: list[str]) -> list[dict]:
    tasks = [{
        "sourceFields": list(fields),
        "connectorOperator": {"S3": "PROJECTION"},
        "taskType": "Filter",
    }]
    for f in fields:
        tasks.append({
            "sourceFields": [f],
            "connectorOperator": {"S3": "NO_OP"},
            "destinationField": f,
            "taskType": "Map",
            "taskProperties": {"SOURCE_DATA_TYPE": "string", "DESTINATION_DATA_TYPE": "string"},
        })
    return tasks


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
