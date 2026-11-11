"""s3-sns-missing-lambda-invoke-permission-blocks-delivery."""

from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-sns-missing-lambda-invoke-permission-blocks-delivery"
GROUP = "s3-event-notifications"
SERVICES = ["lambda", "s3", "sns"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda subscribed to an S3-fed SNS topic without the sns.amazonaws.com invoke permission is
    never invoked while a permissioned twin receives the intact ObjectCreated:Put record; granting
    the permission then makes the same function receive deliveries.
    """
    table = _create_table(ctx)
    role_arn = _create_lambda_role(
        ctx,
        ctx.unique_name("sim2real-s3snsneg-role-"),
        extra_policy={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": table["arn"]}
            ],
        },
    )

    good = _wire_one_side(ctx, table, role_arn, "good", grant_invoke=True)
    bad = _wire_one_side(ctx, table, role_arn, "bad", grant_invoke=False)

    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    def put(side: dict, suffix: str) -> str:
        key = side["key_prefix"] + suffix
        s3.put_object(Bucket=side["bucket"], Key=key, Body=b"behavioral-check-payload")
        return key

    # Fan a single instant to both sides before asserting anything about either.
    good_key_1 = put(good, "1.txt")
    bad_key_1 = put(bad, "1.txt")

    def item_for(key: str):
        return ddb.get_item(TableName=table["name"], Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")

    # Barrier: the good side's first delivery, carrying the S3 record intact through SNS.
    good_item = _poll_until(
        lambda: item_for(good_key_1),
        lambda r: r is not None,
        timeout_s=120,
        interval_s=3.0,
        description=f"positive control item for key {good_key_1!r}",
    )
    assert good_item["bucket"]["S"] == good["bucket"], (
        f"the recorded item carries bucket {good_item['bucket']['S']!r}, expected "
        f"{good['bucket']!r} -- the S3 record inside Sns.Message was not preserved intact"
    )
    assert good_item["eventName"]["S"] == "ObjectCreated:Put", (
        f"the recorded eventName is {good_item['eventName']['S']!r}, expected 'ObjectCreated:Put'"
    )
    assert good_item["topicArn"]["S"] == good["topic_arn"], (
        f"the SNS envelope's TopicArn is {good_item['topicArn']['S']!r}, expected the topic the "
        f"bucket notifies, {good['topic_arn']!r}"
    )

    # Require two FURTHER good-side deliveries before trusting the broken side's absence — one
    # arrival could be luck, a sustained good side while the broken side stays at zero cannot.
    for suffix in ("2.txt", "3.txt"):
        key = put(good, suffix)
        _poll_until(
            lambda k=key: item_for(k),
            lambda r: r is not None,
            timeout_s=60,
            interval_s=3.0,
            description=f"positive control item for key {key!r}",
        )

    assert item_for(bad_key_1) is None, (
        f"item for {bad_key_1!r} exists even though its Lambda was never granted "
        f"lambda:InvokeFunction for sns.amazonaws.com — the subscriber was invoked anyway"
    )

    # Close the loop: grant the withheld permission and re-publish. The SAME broken side's
    # function must now be invoked, proving reachability was never the issue.
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=bad["function_name"],
        StatementId="sns-invoke",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=bad["topic_arn"],
    )
    bad_key_2 = put(bad, "2.txt")
    item = _poll_until(
        lambda: item_for(bad_key_2),
        lambda r: r is not None,
        timeout_s=120,
        interval_s=3.0,
        description=f"repaired item for key {bad_key_2!r}",
    )
    assert item["bucket"]["S"] == bad["bucket"], (
        f"repaired delivery recorded bucket {item['bucket']['S']!r}, expected {bad['bucket']!r}"
    )
    assert item["topicArn"]["S"] == bad["topic_arn"], (
        f"repaired delivery came through {item['topicArn']['S']!r}, expected {bad['topic_arn']!r}"
    )


def _wire_one_side(ctx, table: dict, role_arn: str, label: str, *, grant_invoke: bool) -> dict:
    """Bucket -> SNS topic -> Lambda, wired identically except for the invoke permission."""
    function_name = ctx.unique_name(f"sim2real-s3snsneg-{label}-fn-")
    code = f'''
import json
import boto3

ddb = boto3.client("dynamodb")

def handler(event, context):
    for record in event["Records"]:
        sns = record["Sns"]
        body = json.loads(sns["Message"])
        for s3rec in body.get("Records", []):
            key = s3rec["s3"]["object"]["key"]
            ddb.put_item(
                TableName="{table["name"]}",
                Item={{
                    "pk": {{"S": key}},
                    "bucket": {{"S": s3rec["s3"]["bucket"]["name"]}},
                    "eventName": {{"S": s3rec["eventName"]}},
                    "topicArn": {{"S": sns["TopicArn"]}},
                }},
            )
    return {{"ok": True}}
'''
    # Registered before the function so LIFO reaps the log group after delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, function_name))
    function_arn = _create_function(ctx, function_name, code, role_arn)

    bucket = _make_bucket(ctx, label)

    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name(f"sim2real-s3snsneg-{label}-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic_arn,
                "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
            }],
        }),
    )

    lam = ctx.client("lambda")
    if grant_invoke:
        lam.add_permission(
            FunctionName=function_name,
            StatementId="sns-invoke",
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=function_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    _install_notification(ctx, bucket, {
        "TopicConfigurations": [{
            "Id": "ObjectCreatedToSns",
            "Events": ["s3:ObjectCreated:*"],
            "TopicArn": topic_arn,
        }],
    })

    return {
        "bucket": bucket,
        "topic_arn": topic_arn,
        "function_name": function_name,
        "key_prefix": ctx.unique_name(f"sim2real-s3snsneg-{label}-obj-"),
    }


_LAMBDA_ASSUME_ROLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_table(ctx) -> dict[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-s3snsneg-tbl-")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    return {"name": name, "arn": resp["TableDescription"]["TableArn"]}


def _create_lambda_role(ctx, name: str, extra_policy: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_ASSUME_ROLE_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
    if extra_policy:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-inline", PolicyDocument=json.dumps(extra_policy))

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        if extra_policy:
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=f"{name}-inline")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _zip_code(code: str) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function(ctx, name: str, code: str, role_arn: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 60
    last_exc = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_code(code)},
                Timeout=timeout,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return resp["FunctionArn"]


def _wait_active(ctx, name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg["State"] == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"function {name} Active",
    )


def _reap_log_group(ctx, function_name: str, *, quiet_reads: int = 3, max_rounds: int = 12,
                    interval_s: float = 5.0) -> None:
    """delete_function never removes /aws/lambda/<fn>, and a late log flush can recreate it after
    a delete, so delete until the group has read absent several times running; raise if it keeps
    reappearing."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    quiet = 0
    for _ in range(max_rounds):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= quiet_reads:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _make_bucket(ctx, label: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-s3snsneg-{label}-bkt-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _drop_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    return name


def _drop_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _install_notification(ctx, bucket: str, config: dict, *, deadline_s: float = 90.0) -> None:
    """Put the configuration, retrying S3's eventually-consistent destination-policy read."""
    s3 = ctx.client("s3")
    end = time.monotonic() + deadline_s
    while True:
        try:
            s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration=config)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgument" or time.monotonic() >= end:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
