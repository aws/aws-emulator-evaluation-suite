"""s3-notification-node-commonjs-handler-decodes-the-url-encoded-key."""
from __future__ import annotations

import json
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-node-commonjs-handler-decodes-the-url-encoded-key"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "s3"]

_TAGS = {"sim2real:managed": "true"}

# A CommonJS handler using the Node.js runtime's built-in AWS SDK v3, with no node_modules.
_HANDLER_JS = r"""
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");
const ddb = new DynamoDBClient({});
const TABLE = process.env.REC_TABLE;

exports.handler = async (event) => {
  for (const r of event.Records) {
    const rawKey = r.s3.object.key;
    const decodedKey = decodeURIComponent(rawKey.replace(/\+/g, ' '));
    await ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: {
        pk: { S: rawKey },
        bucket: { S: r.s3.bucket.name },
        decodedKey: { S: decodedKey },
        eventName: { S: r.eventName },
        size: { N: String(r.s3.object.size) },
      },
    }));
  }
};
"""


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, timeout_s, interval_s=2.0, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


def _scan_all(ddb, table: str) -> list[dict]:
    items: list[dict] = []
    kwargs: dict = {"TableName": table}
    while True:
        page = ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3 bucket notification invokes a Node.js CommonJS handler whose event.Records carries
    the URL-encoded key, bucket name, byte size and ObjectCreated:Put eventName, matching the
    object actually written.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html
    """
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    rec_table = ctx.unique_name("sim2real-s3notif-rec-")
    ddb.create_table(
        TableName=rec_table, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=rec_table),
                             "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=rec_table,
                                        WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    rec_arn = ddb.describe_table(TableName=rec_table)["Table"]["TableArn"]

    bucket_name = ctx.unique_name("sim2real-s3notif-bkt-")
    create_kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket_name, Delete={
                "Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_teardown(_empty_and_delete_bucket, "NoSuchBucket"))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    role_name = ctx.unique_name("sim2real-s3notif-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                                Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    basic = f"arn:{role_arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic),
                             "NoSuchEntity"))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": rec_arn},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"),
                             "NoSuchEntity"))

    fn_name = ctx.unique_name("sim2real-s3notif-fn-")
    group = f"/aws/lambda/{fn_name}"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.js", _HANDLER_JS)
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name, Runtime="nodejs24.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=10, MemorySize=256,
                Environment={"Variables": {"REC_TABLE": rec_table}},
                Tags=_TAGS,
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or \
                    "assumed" not in str(exc):
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)

    def _reap_log_group() -> None:
        logs = ctx.client("logs")
        deadline2 = time.monotonic() + 45
        absent = 0
        while absent < 3:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 3:
                assert time.monotonic() < deadline2, "lambda log group never settled absent"
                time.sleep(5)

    ctx.on_cleanup(_reap_log_group)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=fn_name),
                 lambda c: c.get("State") in ("Active", "Failed"), timeout_s=120,
                 what=f"function {fn_name} leaves Pending")
    assert conf.get("State") == "Active", (
        f"function {fn_name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")

    lam.add_permission(FunctionName=fn_name, StatementId="s3-invoke",
                       Action="lambda:InvokeFunction", Principal="s3.amazonaws.com",
                       SourceArn=bucket_arn, SourceAccount=ctx.account)
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [{
                "LambdaFunctionArn": fn_arn,
                "Events": ["s3:ObjectCreated:*"],
            }]
        },
    )

    # A fresh key goes up each round: a notification config change can take some time to arm, and
    # an event that fires before it arms is dropped and never redelivered, so waiting on a single
    # upload races the arming.
    tag = ctx.unique_name("sim2real-s3notif-key")
    body = b"hello-node-s3"
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    item, key, round_n = None, None, 0
    while True:
        round_n += 1
        key = f"dir/{tag}-{round_n} file name.txt"
        s3.put_object(Bucket=bucket_name, Key=key, Body=body)
        ctx.on_cleanup(_teardown(
            lambda k=key: s3.delete_object(Bucket=bucket_name, Key=k), "NoSuchKey"))
        round_end = min(deadline, time.monotonic() + 15.0)
        while time.monotonic() < round_end:
            items = _scan_all(ddb, rec_table)
            matches = [i for i in items if i.get("decodedKey", {}).get("S") == key]
            if matches:
                item = matches[0]
                break
            time.sleep(2)
        if item is not None or time.monotonic() >= deadline:
            break
    if item is None:
        if _budget_spent(ctx):
            raise TimeoutError(
                "S3 notification delivery: the run budget ended first; not graded")
        raise AssertionError(
            f"no PutObject under dir/ over {round_n} round(s) reached the handler within 180s; "
            f"last tried key={key!r}"
        )

    assert item["bucket"]["S"] == bucket_name, (
        f"record's bucket was {item['bucket']['S']!r}, expected {bucket_name!r}"
    )
    assert item["eventName"]["S"] == "ObjectCreated:Put", (
        f"record's eventName was {item['eventName']['S']!r}, expected exactly 'ObjectCreated:Put'"
    )
    assert item["size"]["N"] == str(len(body)), (
        f"record's size was {item['size']['N']!r}, expected {len(body)!r}"
    )
    encoded_key = urllib.parse.quote_plus(key, safe="/")
    assert item["pk"]["S"] == encoded_key, (
        f"the raw notification key was {item['pk']['S']!r}, expected the URL-encoded "
        f"{encoded_key!r} (space -> '+')"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
