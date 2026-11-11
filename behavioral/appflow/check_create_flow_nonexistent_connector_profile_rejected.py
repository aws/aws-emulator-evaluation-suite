"""create-flow-nonexistent-connector-profile-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "create-flow-nonexistent-connector-profile-rejected"
GROUP = "overly-permissive"
SERVICES = ["appflow"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFlow naming a connector profile that was never created raises ResourceNotFoundException
    and leaves no flow, while the same flow as S3-to-S3 without a profile succeeds.
    """
    src_bucket = _create_appflow_bucket(ctx, "src")
    dst_bucket = _create_appflow_bucket(ctx, "dst")
    _put_source_bucket_policy(ctx, src_bucket)
    _put_destination_bucket_policy(ctx, dst_bucket)

    appflow = ctx.client("appflow")
    bad_flow_name = ctx.unique_name("sim2real-af-badprofile-")
    missing_profile_name = ctx.unique_name("sim2real-missing-profile-")

    code, message = _client_error(lambda: appflow.create_flow(
        flowName=bad_flow_name,
        triggerConfig={"triggerType": "OnDemand"},
        sourceFlowConfig={
            "connectorType": "Salesforce",
            "connectorProfileName": missing_profile_name,
            "sourceConnectorProperties": {"Salesforce": {"object": "Account"}},
        },
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=[{
            "sourceFields": ["Id"],
            "connectorOperator": {"Salesforce": "PROJECTION"},
            "taskType": "Filter",
        }],
    ))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a missing connectorProfileName, got {code!r}"
    assert message == f"Connector Profile with name {missing_profile_name} does not exist.", message

    not_found_code, not_found_message = _client_error(lambda: appflow.describe_flow(flowName=bad_flow_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"CreateFlow was rejected, so DescribeFlow({bad_flow_name!r}) must also report "
        f"ResourceNotFoundException (no flow left behind); got {not_found_code!r}"
    )
    assert not_found_message == f"There is no flow with the name {bad_flow_name}", not_found_message

    # Positive control: a flow that needs no connector profile succeeds.
    good_flow_name = ctx.unique_name("sim2real-af-goodprofile-")
    appflow.create_flow(
        flowName=good_flow_name,
        triggerConfig={"triggerType": "OnDemand"},
        sourceFlowConfig=_s3_source_config(src_bucket, "input"),
        destinationFlowConfigList=[_s3_destination_config(dst_bucket, "output")],
        tasks=_passthrough_tasks(["id", "message"]),
    )
    ctx.on_cleanup(lambda: appflow.delete_flow(flowName=good_flow_name, forceDelete=True))
    status = appflow.describe_flow(flowName=good_flow_name)["flowStatus"]
    assert status == "Active", f"expected the S3-to-S3 positive control flow to be Active, got {status!r}"


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
    # S3's CreateBucket rejects an explicit LocationConstraint for the us-east-1 default region.
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
