"""scheduled-flow-start-stop-state-transitions."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "scheduled-flow-start-stop-state-transitions"
GROUP = "state"
SERVICES = ["appflow"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A scheduled flow walks Draft -> Active (StartFlow) -> Suspended (StopFlow),
    with DescribeFlow reflecting each transition."""
    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)

    appflow = ctx.client("appflow")
    flow_name = ctx.unique_name("sim2real-af-flow-")
    create_resp = appflow.create_flow(
        flowName=flow_name,
        triggerConfig={
            "triggerType": "Scheduled",
            "triggerProperties": {"Scheduled": {"scheduleExpression": "rate(6hours)"}},
        },
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=_passthrough_tasks(["id", "message"]),
        tags={"Suite": "sim2real"},
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=flow_name, forceDelete=True))
    assert create_resp["flowStatus"] == "Draft", (
        f"expected a freshly created scheduled flow to default to Draft, got {create_resp['flowStatus']!r}"
    )

    start_resp = appflow.start_flow(flowName=flow_name)
    assert start_resp["flowStatus"] == "Active", (
        f"expected StartFlow's own response to report Active, got {start_resp['flowStatus']!r}"
    )
    active_status = _wait_for_flow_status(appflow, flow_name, {"Active"})
    assert active_status == "Active", (
        f"expected an independent DescribeFlow read to confirm Active, got {active_status!r}"
    )

    stop_resp = appflow.stop_flow(flowName=flow_name)
    assert stop_resp["flowStatus"] == "Suspended", (
        f"expected StopFlow's own response to report Suspended, got {stop_resp['flowStatus']!r}"
    )
    suspended_status = _wait_for_flow_status(appflow, flow_name, {"Suspended"})
    assert suspended_status == "Suspended", (
        f"expected an independent DescribeFlow read to confirm Suspended, got {suspended_status!r}"
    )


def _wait_for_flow_status(appflow, flow_name: str, targets: set[str], timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = appflow.describe_flow(flowName=flow_name)["flowStatus"]
        if last in targets:
            return last
        time.sleep(2.0)
    raise AssertionError(f"flow {flow_name} never reached {targets}, last status was {last}")


def _create_appflow_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-af-{kind}-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint for the us-east-1 default region.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
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
