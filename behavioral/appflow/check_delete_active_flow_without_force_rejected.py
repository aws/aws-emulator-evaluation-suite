"""delete-active-flow-without-force-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-active-flow-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["appflow"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteFlow without forceDelete on an Active scheduled flow raises ConflictException and the
    flow survives; once the flow is Suspended, the identical call succeeds.
    """
    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)

    appflow = ctx.client("appflow")
    flow_name = ctx.unique_name("sim2real-af-flow-")
    appflow.create_flow(
        flowName=flow_name,
        triggerConfig={
            "triggerType": "Scheduled",
            "triggerProperties": {"Scheduled": {"scheduleExpression": "rate(6hours)"}},
        },
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=_passthrough_tasks(["id", "message"]),
    )

    def _cleanup():
        from botocore.exceptions import ClientError
        try:
            appflow.delete_flow(flowName=flow_name, forceDelete=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    appflow.start_flow(flowName=flow_name)
    assert _wait_for_flow_status(appflow, flow_name, {"Active"}) == "Active"

    code, message = _client_error(lambda: appflow.delete_flow(flowName=flow_name))
    assert code == "ConflictException", code
    assert message == (
        "Conflict executing request: Flow is in active state, please set forceDelete to true "
        f"or deactivate the flow: {flow_name}"
    ), message
    # The flow must still exist, unmodified, after the rejected delete.
    status_after_reject = appflow.describe_flow(flowName=flow_name)["flowStatus"]
    assert status_after_reject == "Active", status_after_reject

    # Restore: stop the flow, clearing the Active state that grounded the conflict.
    stop_resp = appflow.stop_flow(flowName=flow_name)
    assert stop_resp["flowStatus"] == "Suspended", stop_resp["flowStatus"]
    assert _wait_for_flow_status(appflow, flow_name, {"Suspended"}) == "Suspended"

    # The identical call -- DeleteFlow, still without forceDelete -- succeeds.
    appflow.delete_flow(flowName=flow_name)
    code3, message3 = _client_error(lambda: appflow.describe_flow(flowName=flow_name))
    assert code3 == "ResourceNotFoundException", code3
    assert message3 == f"There is no flow with the name {flow_name}", message3


def _wait_for_flow_status(appflow, flow_name: str, targets: set[str], timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = appflow.describe_flow(flowName=flow_name)["flowStatus"]
        if last in targets:
            return last
        time.sleep(2.0)
    raise AssertionError(f"flow {flow_name} never reached {targets}, last status was {last}")


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts a call real AWS rejects fails loudly instead of
    reading as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_appflow_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-af-{kind}-").lower().replace("_", "-")
    # us-east-1 is S3's own default region and CreateBucket rejects an explicit
    # LocationConstraint there; this branches on the S3 API's own quirk, not on the
    # check's target region (ctx.region still drives which region gets used).
    if ctx.region == "us-east-1":
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
