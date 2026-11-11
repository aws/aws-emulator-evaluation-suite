"""s3-to-s3-flow-data-transfer-requires-bucket-policy."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "s3-to-s3-flow-data-transfer-requires-bucket-policy"
GROUP = "data-plane"
SERVICES = ["appflow"]

_APPFLOW_PRINCIPAL = "appflow.amazonaws.com"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFlow raises ValidationException when the source bucket policy lacks the AppFlow grant
    and no flow is created; with the grant the identical CreateFlow succeeds and the run moves the
    object's bytes.
    """
    s3 = ctx.client("s3")
    appflow = ctx.client("appflow")

    good_src = _create_appflow_bucket(ctx, "gsrc")
    good_dst = _create_appflow_bucket(ctx, "gdst")
    bad_src = _create_appflow_bucket(ctx, "bsrc")
    _put_source_bucket_policy(ctx, good_src)
    _put_destination_bucket_policy(ctx, good_dst)
    # bad_src intentionally has NO bucket policy granting appflow.amazonaws.com access.

    good_marker = ctx.unique_name("sim2real-good-payload-")
    bad_marker = ctx.unique_name("sim2real-bad-payload-")
    s3.put_object(Bucket=good_src, Key="input/data.csv", Body=f"id,message\n1,{good_marker}\n".encode())
    s3.put_object(Bucket=bad_src, Key="input/data.csv", Body=f"id,message\n1,{bad_marker}\n".encode())

    good_flow = ctx.unique_name("sim2real-af-good-")
    bad_flow = ctx.unique_name("sim2real-af-bad-")

    # Positive control: an identically-shaped flow with a granted source policy
    # creates and actually moves the marker byte-for-byte to the destination.
    _create_flow(appflow, good_flow, good_src, good_dst, "output")
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=good_flow, forceDelete=True))
    good_execution_id = appflow.start_flow(flowName=good_flow)["executionId"]
    good_record = _wait_for_execution(appflow, good_flow, good_execution_id, {"Successful", "Error"})
    assert good_record["executionStatus"] == "Successful", good_record
    good_content = _read_prefix(s3, good_dst, "output")
    assert good_marker in good_content, good_content

    # Break exactly one thing: bad_src has no AppFlow resource policy. CreateFlow
    # itself is rejected — real AWS validates the policy at definition time, not
    # at run time — and the specific error names the missing s3 actions.
    code, message = _client_error(lambda: _create_flow(appflow, bad_flow, bad_src, good_dst, "output-bad"))
    assert code == "ValidationException", code
    # The message names the IAM service principal the policy must grant, not an endpoint host.
    principal = _APPFLOW_PRINCIPAL
    expected_message = (
        f"Create Flow request failed: [The provided S3 Bucket [{bad_src}] is missing the following "
        "permitted actions: [s3:listbucket, s3:getobject]\n. These policies must be applied to the "
        f"[{principal}] service principal and must be attached to all the following "
        f"resources: [arn:aws:s3:::{bad_src}, arn:aws:s3:::{bad_src}/*]]"
    )
    assert message == expected_message, message

    # Effect absent, via an independent read: the flow was never created.
    flow_names = {f["flowName"] for f in appflow.list_flows()["flows"]}
    assert bad_flow not in flow_names, flow_names
    not_found_code, not_found_message = _client_error(lambda: appflow.describe_flow(flowName=bad_flow))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_message == f"There is no flow with the name {bad_flow}", not_found_message

    # Restore: grant bad_src the identical policy good_src already has, then
    # retry the SAME CreateFlow call and demand it succeeds end to end —
    # proving the earlier rejection was caused by the missing policy alone.
    _put_source_bucket_policy(ctx, bad_src)
    _create_flow(appflow, bad_flow, bad_src, good_dst, "output-bad")
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=bad_flow, forceDelete=True))
    restored_execution_id = appflow.start_flow(flowName=bad_flow)["executionId"]
    restored_record = _wait_for_execution(appflow, bad_flow, restored_execution_id, {"Successful", "Error"})
    assert restored_record["executionStatus"] == "Successful", restored_record
    restored_content = _read_prefix(s3, good_dst, "output-bad")
    assert bad_marker in restored_content, restored_content


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


def _create_flow(appflow, flow_name: str, src_bucket: str, dst_bucket: str, dst_prefix: str) -> None:
    appflow.create_flow(
        flowName=flow_name,
        triggerConfig={"triggerType": "OnDemand"},
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, dst_prefix)],
        tasks=_passthrough_tasks(["id", "message"]),
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


def _read_prefix(s3, bucket: str, prefix: str) -> str:
    paginator = s3.get_paginator("list_objects_v2")
    out = b""
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            out += s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
    return out.decode("utf-8", errors="replace")


def _create_appflow_bucket(ctx: Any, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-af-{kind}-").lower().replace("_", "-")
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
