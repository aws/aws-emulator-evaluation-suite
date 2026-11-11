"""processing-configuration-parameter-normalization-and-update-replaces-block."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "processing-configuration-parameter-normalization-and-update-replaces-block"
GROUP = "overly-permissive"
SERVICES = ["firehose"]

TRUST_POLICY_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

TRUST_POLICY_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

_HANDLER = """
    def lambda_handler(event, context):
        return {"records": [
            {"recordId": r["recordId"], "result": "Ok", "data": r["data"]} for r in event["records"]
        ]}
"""


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last observed: {last!r}")


def _bucket_arn(name):
    return f"arn:aws:s3:::{name}"


def _make_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-pc-bkt-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behavioral-check", "Value": CHECK}]}
    )

    def _teardown():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown)
    return name


def _delete_role(ctx, role_name):
    """Teardown: attached and inline policies first, then the role; a failure RAISES."""
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _delivery_role_arn(ctx, *, lambda_arn=None):
    """Create a real IAM role Firehose can assume, with S3 write and (optionally) permission
    to invoke the given Lambda function; register teardown immediately."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-pc-role-")
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
            ],
            "Resource": "*",
        }
    ]
    if lambda_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"],
                "Resource": [lambda_arn, f"{lambda_arn}:*"],
            }
        )
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY_FIREHOSE),
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return resp["Role"]["Arn"]


def _wait_function_active(ctx, name, timeout_s=120.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} reaches Active",
    )


def _reap_log_group(ctx, group, *, rounds=4, interval_s=4.0):
    logs = ctx.client("logs")
    for _ in range(rounds):
        _try(lambda: logs.delete_log_group(logGroupName=group))
        time.sleep(interval_s)
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in found):
            return
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _create_processor_lambda(ctx):
    """A trivial pass-through transform Lambda, real enough for Firehose to validate and
    reference as a processor target."""
    role = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-pc-lrole-")
    resp = role.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY_LAMBDA),
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    role.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    name = ctx.unique_name("sim2real-behav-fh-pc-fn-")
    lam = ctx.client("lambda")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(_HANDLER))
    deadline = time.monotonic() + 120
    while True:
        try:
            fn = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=resp["Role"]["Arn"],
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=60,
                MemorySize=128,
                Tags={"sim2real-behavioral-check": CHECK},
            )
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: _try(lambda: lam.delete_function(FunctionName=name)))
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    _wait_function_active(ctx, name)
    return fn["FunctionArn"]


#: Error codes that mean a teardown step's resource is already gone.
_GONE = {"NoSuchEntity", "NoSuchBucket", "ResourceNotFoundException", "EntityNotFoundException"}


def _try(fn):
    """One teardown step: a resource already gone is done; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE:
            raise


def _delete_stream(ctx, name):
    _try(lambda: ctx.client("firehose").delete_delivery_stream(
        DeliveryStreamName=name, AllowForceDelete=True))


def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]


def _wait_active(ctx, name, timeout_s=180, interval_s=3):
    desc = _poll_until(
        lambda: _describe(ctx, name),
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"delivery stream {name} reaches ACTIVE",
    )
    return desc


def _create_stream(ctx, name, dest_config):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 120
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))


def _param_map(parameters):
    return {p["ParameterName"]: p["ParameterValue"] for p in parameters}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda processor given only LambdaArn and buffer parameters comes back with NumberOfRetries
    "3" and RoleArn set to the delivery role; an update naming only Enabled=false empties the
    processor list, leaves RoleARN and BufferingHints untouched, and bumps VersionId by one.
    """
    bucket = _make_bucket(ctx)
    fn_arn = _create_processor_lambda(ctx)
    role_arn = _delivery_role_arn(ctx, lambda_arn=fn_arn)
    name = ctx.unique_name("sim2real-behav-fh-pc-stream-")

    _create_stream(
        ctx,
        name,
        {
            "RoleARN": role_arn,
            "BucketARN": _bucket_arn(bucket),
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "ProcessingConfiguration": {
                "Enabled": True,
                "Processors": [
                    {
                        "Type": "Lambda",
                        "Parameters": [
                            {"ParameterName": "BufferIntervalInSeconds", "ParameterValue": "70"},
                            {"ParameterName": "BufferSizeInMBs", "ParameterValue": "2"},
                            {"ParameterName": "LambdaArn", "ParameterValue": fn_arn},
                        ],
                    }
                ],
            },
        },
    )
    desc = _wait_active(ctx, name)
    ext = desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    processing = ext["ProcessingConfiguration"]
    assert processing["Enabled"] is True, f"ProcessingConfiguration must echo enabled: {processing!r}"
    assert len(processing["Processors"]) == 1, f"expected exactly one processor: {processing!r}"
    params = processing["Processors"][0]["Parameters"]
    names = [p["ParameterName"] for p in params]
    # ProcessorParameterList documents no order: the parameter names are compared as a set.
    assert sorted(names) == sorted(
        ["LambdaArn", "NumberOfRetries", "RoleArn", "BufferSizeInMBs", "BufferIntervalInSeconds"]
    ), (
        f"the service must normalize the processor's parameters to LambdaArn, NumberOfRetries, "
        f"RoleArn, BufferSizeInMBs and BufferIntervalInSeconds, each once, got {names!r}"
    )
    pmap = _param_map(params)
    assert pmap["LambdaArn"] == fn_arn, f"LambdaArn must echo {fn_arn!r}, got {pmap!r}"
    assert pmap["NumberOfRetries"] == "3", (
        f"NumberOfRetries must default to '3' when the caller does not supply it, got "
        f"{pmap.get('NumberOfRetries')!r}: {pmap!r}"
    )
    assert pmap["RoleArn"] == role_arn, (
        f"RoleArn must be stamped to the delivery stream's own role {role_arn!r} when the "
        f"caller does not supply it, got {pmap.get('RoleArn')!r}: {pmap!r}"
    )
    assert pmap["BufferSizeInMBs"] == "2", pmap
    assert pmap["BufferIntervalInSeconds"] == "70", pmap

    version_id = desc["VersionId"]
    destination_id = desc["Destinations"][0]["DestinationId"]
    ctx.client("firehose").update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=version_id,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={"ProcessingConfiguration": {"Enabled": False}},
    )
    desc2 = _describe(ctx, name)
    ext2 = desc2["Destinations"][0]["ExtendedS3DestinationDescription"]
    processing2 = ext2["ProcessingConfiguration"]
    assert processing2["Enabled"] is False, f"ProcessingConfiguration.Enabled must flip to False: {processing2!r}"
    assert processing2.get("Processors") == [], (
        f"an UpdateDestination that supplies ProcessingConfiguration with no Processors field "
        f"must REPLACE the stored processor list with an empty one, not merge over it and keep "
        f"the previous Lambda processor: {processing2!r}"
    )
    assert ext2["RoleARN"] == role_arn, (
        f"the destination's own RoleARN must be untouched by an update that only names "
        f"ProcessingConfiguration, got {ext2.get('RoleARN')!r}"
    )
    assert ext2["BufferingHints"] == {"SizeInMBs": 1, "IntervalInSeconds": 60}, (
        f"BufferingHints must be untouched by an update that only names ProcessingConfiguration, "
        f"got {ext2.get('BufferingHints')!r}"
    )
    assert int(desc2["VersionId"]) == int(version_id) + 1, (
        f"a successful UpdateDestination must bump VersionId from {version_id!r}, got "
        f"{desc2['VersionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
