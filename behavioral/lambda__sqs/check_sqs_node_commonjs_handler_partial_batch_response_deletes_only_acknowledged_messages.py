"""sqs-node-commonjs-handler-partial-batch-response-deletes-only-acknowledged-messages."""
from __future__ import annotations

import json
import time
import uuid
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-node-commonjs-handler-partial-batch-response-deletes-only-acknowledged-messages"
GROUP = "event-propagation"
SERVICES = ["lambda", "sqs"]

_TAGS = {"sim2real:managed": "true"}

# A CommonJS handler (no ESM import, no bundling): the Lambda Node.js runtime ships the AWS SDK
# v3 built in, so `require` resolves with no node_modules in the deployment package.
_HANDLER_JS = r"""
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");
const ddb = new DynamoDBClient({});
const TABLE = process.env.REC_TABLE;

exports.handler = async (event) => {
  const failures = [];
  for (const r of event.Records) {
    const receiveCount = parseInt(r.attributes.ApproximateReceiveCount, 10);
    await ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: {
        pk: { S: `${r.messageId}#${receiveCount}` },
        body: { S: r.body },
      },
    }));
    if (r.body.startsWith("bad-")) {
      failures.push({ itemIdentifier: r.messageId });
    }
  }
  return { batchItemFailures: failures };
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
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A standard-queue ESM with ReportBatchItemFailures, driving a Node.js CommonJS handler,
    deletes only the messages the handler acknowledged: an unreported message is redelivered,
    an acknowledged one never is.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
    """
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    rec_table = ctx.unique_name("sim2real-sqspbr-rec-")
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

    queue_name = ctx.unique_name("sim2real-sqspbr-src-")
    queue_url = sqs.create_queue(QueueName=queue_name, Attributes={
        "VisibilityTimeout": "8",
    }, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-sqspbr-role-")
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
            {"Effect": "Allow",
             "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes",
                        "sqs:ChangeMessageVisibility"],
             "Resource": queue_arn},
            {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": rec_arn},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"),
                             "NoSuchEntity"))

    fn_name = ctx.unique_name("sim2real-sqspbr-fn-")
    group = f"/aws/lambda/{fn_name}"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.js", _HANDLER_JS)
    timeout_s = _budget_s(ctx, 90)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name, Runtime="nodejs24.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=6, MemorySize=256,
                Environment={"Variables": {"REC_TABLE": rec_table}},
                Tags=_TAGS,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or \
                    "assumed" not in str(exc):
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateFunction: the run budget ended first; not graded"
                    ) from exc
                raise
            time.sleep(2)

    def _reap_log_group() -> None:
        logs = ctx.client("logs")
        timeout2_s = _budget_s(ctx, 180)
        deadline2 = time.monotonic() + timeout2_s
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
                if time.monotonic() >= deadline2:
                    raise AssertionError(
                        f"log group {group} still present after {timeout2_s:.0f}s of deletes; "
                        f"{absent} clean reads"
                    )
                time.sleep(2)

    ctx.on_cleanup(_reap_log_group)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    tag = uuid.uuid4().hex[:8]
    good_a, good_b = f"good-a-{tag}", f"good-b-{tag}"
    bad_a, bad_b = f"bad-a-{tag}", f"bad-b-{tag}"

    esm = lam.create_event_source_mapping(
        FunctionName=fn_name, EventSourceArn=queue_arn, BatchSize=10,
        FunctionResponseTypes=["ReportBatchItemFailures"])
    uuid_esm = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid_esm),
                             "ResourceNotFoundException"))
    timeout_s = _budget_s(ctx, 90)
    deadline = time.monotonic() + timeout_s
    while True:
        state = lam.get_event_source_mapping(UUID=uuid_esm)["State"]
        if state == "Enabled":
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    "event source mapping reaching Enabled: the run budget ended first; "
                    "not graded"
                )
            raise AssertionError(f"event source mapping stuck in state {state!r}")
        time.sleep(2)

    for body in (good_a, good_b, bad_a, bad_b):
        sqs.send_message(QueueUrl=queue_url, MessageBody=body)

    timeout_s = _budget_s(ctx, 240)
    deadline = time.monotonic() + timeout_s
    items: list[dict] = []
    while True:
        items = _scan_all(ddb, rec_table)
        bodies = [i["body"]["S"] for i in items]
        bad_counts = {
            b: sum(1 for x in bodies if x == b) for b in (bad_a, bad_b)
        }
        if good_a in bodies and good_b in bodies and all(c >= 2 for c in bad_counts.values()):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    "waiting for the full sequence: the run budget ended first; not graded"
                )
            raise AssertionError(
                f"timed out waiting for the full sequence; bodies recorded so far={sorted(bodies)!r}"
            )
        time.sleep(2)

    items = _scan_all(ddb, rec_table)
    bodies = [i["body"]["S"] for i in items]
    assert bodies.count(good_a) == 1, (
        f"acknowledged message {good_a!r} was recorded {bodies.count(good_a)} time(s), expected "
        f"exactly 1 -- a batchItemFailures response must delete every message it did not report"
    )
    assert bodies.count(good_b) == 1, (
        f"acknowledged message {good_b!r} was recorded {bodies.count(good_b)} time(s), expected "
        f"exactly 1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
