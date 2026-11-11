"""describe-flow-reports-task-and-source-config-fidelity."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "describe-flow-reports-task-and-source-config-fidelity"
GROUP = "control-plane"
SERVICES = ["appflow"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFlow echoes back the exact source/destination bucket configuration and
    task list that were supplied at CreateFlow time (structural round-trip fidelity)."""
    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)

    appflow = ctx.client("appflow")
    flow_name = ctx.unique_name("sim2real-af-flow-")
    tasks = _passthrough_tasks(["id", "message"])
    appflow.create_flow(
        flowName=flow_name,
        description="sim2real fidelity check flow",
        triggerConfig={"triggerType": "OnDemand"},
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=tasks,
        tags={"Suite": "sim2real"},
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=flow_name, forceDelete=True))

    described = appflow.describe_flow(flowName=flow_name)
    assert described["description"] == "sim2real fidelity check flow", (
        f"description not echoed: {described['description']!r}"
    )
    assert described["triggerConfig"]["triggerType"] == "OnDemand", (
        f"triggerType not echoed: {described['triggerConfig']['triggerType']!r}"
    )

    src_props = described["sourceFlowConfig"]["sourceConnectorProperties"]["S3"]
    assert src_props["bucketName"] == src_bucket, (
        f"source bucketName mismatch: expected {src_bucket!r}, got {src_props['bucketName']!r}"
    )
    assert src_props["bucketPrefix"] == "input", (
        f"source bucketPrefix mismatch: expected 'input', got {src_props['bucketPrefix']!r}"
    )

    dst_cfg = described["destinationFlowConfigList"][0]["destinationConnectorProperties"]["S3"]
    assert dst_cfg["bucketName"] == dst_bucket, (
        f"destination bucketName mismatch: expected {dst_bucket!r}, got {dst_cfg['bucketName']!r}"
    )
    assert dst_cfg["bucketPrefix"] == "output", (
        f"destination bucketPrefix mismatch: expected 'output', got {dst_cfg['bucketPrefix']!r}"
    )

    described_tasks = described["tasks"]
    assert len(described_tasks) == len(tasks), (
        f"task count mismatch: expected {len(tasks)}, got {len(described_tasks)}"
    )
    task_types = [t["taskType"] for t in described_tasks]
    assert task_types == ["Filter", "Map", "Map"], (
        f"task type order mismatch: expected ['Filter', 'Map', 'Map'], got {task_types!r}"
    )
    filter_task = described_tasks[0]
    assert sorted(filter_task["sourceFields"]) == ["id", "message"], (
        f"filter sourceFields mismatch: expected ['id', 'message'], got {sorted(filter_task['sourceFields'])!r}"
    )
    map_dest_fields = sorted(t["destinationField"] for t in described_tasks[1:])
    assert map_dest_fields == ["id", "message"], (
        f"map destinationField set mismatch: expected ['id', 'message'], got {map_dest_fields!r}"
    )


def _create_appflow_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-af-{kind}-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "appflow-describe-flow-fidelity"}]})
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
