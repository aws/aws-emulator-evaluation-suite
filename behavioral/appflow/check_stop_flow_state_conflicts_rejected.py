"""stop-flow-state-conflicts-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "stop-flow-state-conflicts-rejected"
GROUP = "overly-permissive"
SERVICES = ["appflow"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopFlow raises ConflictException for an on-demand flow and for an already-Suspended
    scheduled flow, while an Active scheduled flow stops successfully.
    """
    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)
    appflow = ctx.client("appflow")

    # (1) on-demand flow: StopFlow is unconditionally rejected as a state conflict.
    ondemand_flow = ctx.unique_name("sim2real-af-ondemand-")
    appflow.create_flow(
        flowName=ondemand_flow,
        triggerConfig={"triggerType": "OnDemand"},
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=_passthrough_tasks(["id", "message"]),
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=ondemand_flow, forceDelete=True))
    _wait_for_flow_status(appflow, ondemand_flow, {"Active"})

    code, message = _client_error(lambda: appflow.stop_flow(flowName=ondemand_flow))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == f"Conflict executing request: Flow is already deactivated: {ondemand_flow}", message
    status = appflow.describe_flow(flowName=ondemand_flow)["flowStatus"]
    assert status == "Active", f"expected on-demand flow to remain Active after rejected StopFlow, got {status!r}"

    # (2) scheduled flow: positive control (Active -> Suspended succeeds), then a
    # second StopFlow on the already-Suspended flow is rejected as a state conflict.
    scheduled_flow = ctx.unique_name("sim2real-af-scheduled-")
    appflow.create_flow(
        flowName=scheduled_flow,
        triggerConfig={
            "triggerType": "Scheduled",
            "triggerProperties": {"Scheduled": {"scheduleExpression": "rate(6hours)"}},
        },
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output2")],
        tasks=_passthrough_tasks(["id", "message"]),
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=scheduled_flow, forceDelete=True))
    appflow.start_flow(flowName=scheduled_flow)
    _wait_for_flow_status(appflow, scheduled_flow, {"Active"})

    stop_resp = appflow.stop_flow(flowName=scheduled_flow)
    assert stop_resp["flowStatus"] == "Suspended", f"expected Suspended, got {stop_resp.get('flowStatus')!r}"
    _wait_for_flow_status(appflow, scheduled_flow, {"Suspended"})

    code2, message2 = _client_error(lambda: appflow.stop_flow(flowName=scheduled_flow))
    assert code2 == "ConflictException", f"expected ConflictException, got {code2!r}"
    assert message2 == f"Conflict executing request: Flow is already deactivated: {scheduled_flow}", message2
    status2 = appflow.describe_flow(flowName=scheduled_flow)["flowStatus"]
    assert status2 == "Suspended", f"expected flow to remain Suspended after rejected re-StopFlow, got {status2!r}"

    # Restore leg: resume the same flow and prove the identical StopFlow call
    # succeeds, showing the ConflictException above was about the Suspended
    # state specifically, not an unconditional rejection of this flow.
    appflow.start_flow(flowName=scheduled_flow)
    _wait_for_flow_status(appflow, scheduled_flow, {"Active"})
    stop_resp2 = appflow.stop_flow(flowName=scheduled_flow)
    assert stop_resp2["flowStatus"] == "Suspended", (
        f"expected Suspended after restore-then-stop, got {stop_resp2.get('flowStatus')!r}"
    )
    status3 = appflow.describe_flow(flowName=scheduled_flow)["flowStatus"]
    assert status3 == "Suspended", f"expected Suspended via independent read after restore-then-stop, got {status3!r}"


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
    if ctx.region == "us-east-1":  # S3 CreateBucket forbids LocationConstraint specifically for us-east-1
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
