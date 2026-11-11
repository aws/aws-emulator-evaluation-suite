"""update-flow-updates-task-configuration."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "update-flow-updates-task-configuration"
GROUP = "state"
SERVICES = ["appflow"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFlow persists a changed description and task list, and DescribeFlow returns the
    new configuration rather than the one from CreateFlow; the destination connector object is
    immutable, so it stays fixed."""
    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)

    appflow = ctx.client("appflow")
    flow_name = ctx.unique_name("sim2real-af-flow-")
    trigger_config = {"triggerType": "OnDemand"}
    dest_config = [_s3_destination_config(dst_bucket, "output", "JSON")]
    appflow.create_flow(
        flowName=flow_name,
        description="before-update",
        triggerConfig=trigger_config,
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=dest_config,
        tasks=_passthrough_tasks(["id", "message"]),
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=flow_name, forceDelete=True))

    before = appflow.describe_flow(flowName=flow_name)
    before_dst = before["destinationFlowConfigList"][0]["destinationConnectorProperties"]["S3"]
    assert before_dst["bucketPrefix"] == "output", (
        f"expected pre-update destination bucketPrefix 'output', got {before_dst['bucketPrefix']!r}"
    )
    assert before["description"] == "before-update", (
        f"expected pre-update description 'before-update', got {before['description']!r}"
    )
    assert len(before["tasks"]) == 3, (
        f"expected 3 pre-update tasks (filter + 2 field maps), got {len(before['tasks'])}"
    )

    try:
        update_resp = appflow.update_flow(
            flowName=flow_name,
            description="after-update",
            triggerConfig=trigger_config,
            sourceFlowConfig=_s3_source_config(src_bucket, "input"),
            destinationFlowConfigList=dest_config,
            tasks=_passthrough_tasks(["id"]),
        )
    except Exception as err:  # surface full message for debugging root cause
        msg = getattr(err, "response", {}).get("Error", {}).get("Message", str(err))
        raise AssertionError(f"update_flow failed ({len(msg)} chars): {msg!r}") from err
    assert update_resp["flowStatus"] == "Active", (
        f"expected flowStatus 'Active' after update, got {update_resp['flowStatus']!r}"
    )

    after = appflow.describe_flow(flowName=flow_name)
    after_dst = after["destinationFlowConfigList"][0]["destinationConnectorProperties"]["S3"]
    assert after_dst["bucketPrefix"] == "output", (
        f"expected post-update destination bucketPrefix to stay 'output', got {after_dst['bucketPrefix']!r}"
    )
    assert after["description"] == "after-update", (
        f"expected post-update description 'after-update', got {after['description']!r}"
    )
    assert len(after["tasks"]) == 2, (
        f"expected 2 post-update tasks (filter + 1 field map, down from 3), got {len(after['tasks'])}"
    )


def _create_appflow_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-af-{kind}-").lower().replace("_", "-")
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


def _s3_destination_config(bucket: str, prefix: str, file_type: str) -> dict:
    return {
        "connectorType": "S3",
        "destinationConnectorProperties": {
            "S3": {"bucketName": bucket, "bucketPrefix": prefix, "s3OutputFormatConfig": {"fileType": file_type}}
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
