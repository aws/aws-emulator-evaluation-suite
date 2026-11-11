"""sqs-fifo-esm-partial-batch-response-deletes-a-later-same-group-success-despite-an-earlier-failure."""
from __future__ import annotations

import json
import time
import uuid
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = ("sqs-fifo-esm-partial-batch-response-deletes-a-later-same-group-success-"
         "despite-an-earlier-failure")
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "sqs"]

_TAGS = {"sim2real:managed": "true"}
_HANDLER_JS = r"""
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
const ddb = new DynamoDBClient({});
const TABLE = process.env.REC_TABLE;

export const handler = async (event, context) => {
  const failures = [];
  for (const r of event.Records) {
    const receiveCount = parseInt(r.attributes.ApproximateReceiveCount, 10);
    await ddb.send(new PutItemCommand({
      TableName: TABLE,
      Item: {
        pk: { S: `${r.messageId}#${receiveCount}` },
        group: { S: r.attributes.MessageGroupId },
        body: { S: r.body },
        receiveCount: { N: String(receiveCount) },
        ts: { N: String(Date.now()) },
        invocationId: { S: context.awsRequestId },
      },
    }));
    if (r.body.startsWith("poison") && receiveCount < 2) {
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


def _scan_all(ddb, table: str) -> list[dict]:
    items: list[dict] = []
    kwargs: dict = {"TableName": table}
    while True:
        page = ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO ESM using ReportBatchItemFailures deletes a message the function processed
    successfully even when it sits behind a same-group message the function reported failed
    in the identical invocation: Lambda does not withhold the later success on its own.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
    """
    ddb = ctx.client("dynamodb")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    rec_table = ctx.unique_name("sim2real-fifopbr-rec-")
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

    queue_name = ctx.unique_name("sim2real-fifopbr-src-") + ".fifo"
    queue_url = sqs.create_queue(QueueName=queue_name, Attributes={
        "FifoQueue": "true", "VisibilityTimeout": "20",
    }, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-fifopbr-role-")
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

    fn_name = ctx.unique_name("sim2real-fifopbr-fn-")
    group = f"/aws/lambda/{fn_name}"
    zip_buf = BytesIO()
    with ZipFile(zip_buf, "w", ZIP_DEFLATED) as zf:
        zf.writestr("index.mjs", _HANDLER_JS)
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=15, MemorySize=256,
                Environment={"Variables": {"REC_TABLE": rec_table}},
                Tags=_TAGS,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or \
                    "assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)

    def _reap_log_group() -> None:
        logs = ctx.client("logs")
        deadline2 = time.monotonic() + 180
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
    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    tag = uuid.uuid4().hex[:8]
    group_a, group_b = f"grpA-{tag}", f"grpB-{tag}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=f"poison-{tag}",
                      MessageGroupId=group_a, MessageDeduplicationId=f"a1-{tag}")
    sqs.send_message(QueueUrl=queue_url, MessageBody=f"trailing-ok-{tag}",
                      MessageGroupId=group_a, MessageDeduplicationId=f"a2-{tag}")
    sqs.send_message(QueueUrl=queue_url, MessageBody=f"other-group-ok-{tag}",
                      MessageGroupId=group_b, MessageDeduplicationId=f"b1-{tag}")

    esm = lam.create_event_source_mapping(
        FunctionName=fn_name, EventSourceArn=queue_arn, BatchSize=10,
        FunctionResponseTypes=["ReportBatchItemFailures"])
    uuid_esm = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid_esm),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_event_source_mapping(UUID=uuid_esm)["State"]
        if state == "Enabled":
            break
        assert time.monotonic() < deadline, f"event source mapping stuck in state {state!r}"
        time.sleep(2)

    deadline = time.monotonic() + 240
    a1_counts: set[int] = set()
    a2_present = False
    b1_present = False
    while True:
        items = _scan_all(ddb, rec_table)
        a1_counts = {int(i["receiveCount"]["N"]) for i in items if i["body"]["S"].startswith("poison")}
        a2_present = any(i["body"]["S"].startswith("trailing-ok") for i in items)
        b1_present = any(i["body"]["S"].startswith("other-group-ok") for i in items)
        if a2_present and b1_present and any(c >= 2 for c in a1_counts):
            break
        assert time.monotonic() < deadline, (
            f"timed out waiting for the full sequence; a1 receive counts seen={sorted(a1_counts)!r}, "
            f"trailing same-group item seen={a2_present!r}, other-group item seen={b1_present!r}"
        )
        time.sleep(3)

    items = _scan_all(ddb, rec_table)
    a1_first_attempts = [i for i in items
                         if i["body"]["S"].startswith("poison") and i["receiveCount"]["N"] == "1"]
    a2_records = [i for i in items if i["body"]["S"].startswith("trailing-ok")]
    assert 1 in a1_counts, f"the poison message's first attempt was never recorded: {sorted(a1_counts)!r}"
    assert any(c >= 2 for c in a1_counts), (
        f"the poison message was never retried to a later success: receive counts {sorted(a1_counts)!r}"
    )
    assert len(a2_records) == 1 and a2_records[0]["receiveCount"]["N"] == "1", (
        f"the trailing same-group success was recorded {len(a2_records)} time(s) "
        f"({[r['receiveCount']['N'] for r in a2_records]!r}); it is deleted on its one successful "
        "delivery and never redelivered, even though the message ahead of it in its group failed"
    )
    assert len(a1_first_attempts) == 1, (
        f"the poison message's first attempt was recorded {len(a1_first_attempts)} time(s), expected 1"
    )
    a1_first_invocation = a1_first_attempts[0]["invocationId"]["S"]
    a2_invocation = a2_records[0]["invocationId"]["S"]
    assert a2_invocation == a1_first_invocation, (
        "the trailing same-group success was not processed in the same invocation as the poison "
        f"message's first (failing) attempt (a2 invocation={a2_invocation!r}, a1 first-attempt "
        f"invocation={a1_first_invocation!r}); the scenario this check exercises -- a reported "
        "failure and a later same-group success in one invocation -- did not occur as set up"
    )
    a1_success_ts = min(int(i["ts"]["N"]) for i in items
                        if i["body"]["S"].startswith("poison") and int(i["receiveCount"]["N"]) >= 2)
    b1_ts = min(int(i["ts"]["N"]) for i in items if i["body"]["S"].startswith("other-group-ok"))
    assert b1_ts < a1_success_ts, (
        f"the independent group's message (ts={b1_ts}) was held back until the poisoned group "
        f"resolved (ts={a1_success_ts}); an independent message group must not be blocked by another"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
