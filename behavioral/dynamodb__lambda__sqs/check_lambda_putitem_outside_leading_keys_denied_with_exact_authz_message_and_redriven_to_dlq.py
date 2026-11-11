"""lambda-putitem-outside-leading-keys-denied-with-exact-authz-message-and-redriven-to-dlq."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-putitem-outside-leading-keys-denied-with-exact-authz-message-and-redriven-to-dlq"
GROUP = "fault-injection"
SERVICES = ["dynamodb", "lambda", "sqs"]

_RUNTIME = "python3.12"
# The queue visibility timeout must be at least the function timeout; both are short so the
# redrive after maxReceiveCount failed deliveries takes seconds.
_FN_TIMEOUT_S = 3
_QUEUE_VISIBILITY_TIMEOUT_S = 5
_MAX_RECEIVE_COUNT = 2

# DynamoDB's code is AccessDeniedException (not IAM's AccessDenied); the message names the assumed
# role session (the function name) and the table ARN. The DLQ's first receive reports count 3:
# the two source-queue receives carry over.
_AUTHZ_CODE = "AccessDeniedException"
_AUTHZ_HTTP_STATUS = 400
_AUTHZ_MESSAGE = (
    "User: {principal} is not authorized to perform: dynamodb:PutItem on resource: {table_arn} "
    "because no identity-based policy allows the dynamodb:PutItem action"
)
_DLQ_RECEIVE_COUNT = "3"

_FAIL_MARKER = "SIM2REAL_PUT_FAILED"

# The role grants dynamodb:PutItem only for items whose partition key is this value.
_ALLOWED_PK = "A"
# Poll deadlines, not sleeps.
_IAM_ROLE_PROPAGATION_BUDGET_S = 120.0
_BASELINE_TIMEOUT_S = 180.0
_DENIAL_TIMEOUT_S = 120.0
_DLQ_LANDING_TIMEOUT_S = 240.0

_HANDLER = '''
import json, os, boto3, botocore

ddb = boto3.client("dynamodb")
TABLE = os.environ["TABLE"]


def handler(event, context):
    for rec in event["Records"]:
        body = json.loads(rec["body"])
        common = {"pk": body["pk"], "rid": context.aws_request_id,
                  "msgid": rec["messageId"],
                  "recv": rec["attributes"].get("ApproximateReceiveCount")}
        try:
            ddb.put_item(TableName=TABLE,
                         Item={"pk": {"S": body["pk"]}, "payload": {"S": body["payload"]}})
        except botocore.exceptions.ClientError as err:
            common["code"] = err.response["Error"]["Code"]
            common["message"] = err.response["Error"]["Message"]
            common["status"] = err.response["ResponseMetadata"]["HTTPStatusCode"]
            print("SIM2REAL_PUT_FAILED " + json.dumps(common))
            raise
        print("SIM2REAL_PUT_OK " + json.dumps(common))
    return {"ok": True}
'''


# timing:real-time — visibility: 5 s
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Lambda whose role allows dynamodb:PutItem only for one partition key writes that key,
    is denied any other with the exact authz message, leaves that item absent, and its message
    is redelivered after the 5 s visibility timeout until maxReceiveCount redrives it to the DLQ.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    ddb = ctx.client("dynamodb")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    table = ctx.unique_name("sim2real-g1-tbl-")
    ddb.create_table(TableName=table, BillingMode="PAY_PER_REQUEST",
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}])
    ctx.on_cleanup(lambda: _delete_table_quiet(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-g1-dlq-"),
                               tags={"sim2real": "g1-fault-injection"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quiet(sqs, dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url,
                                       AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-g1-src-"),
        Attributes={"VisibilityTimeout": str(_QUEUE_VISIBILITY_TIMEOUT_S),
                    "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn,
                                                 "maxReceiveCount": str(_MAX_RECEIVE_COUNT)})},
        tags={"sim2real": "g1-fault-injection"})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quiet(sqs, src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url,
                                       AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-g1-fnrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="base", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": "*"},
            {"Effect": "Allow",
             "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
             "Resource": src_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="base"))
    put_policy_doc = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn,
         "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [_ALLOWED_PK]}}}]})
    iam.put_role_policy(RoleName=role_name, PolicyName="ddbput", PolicyDocument=put_policy_doc)
    ctx.on_cleanup(lambda: _delete_role_policy_quiet(iam, role_name, "ddbput"))

    fn = ctx.unique_name("sim2real-g1-fn-")
    _create_function(ctx, lam, fn, role_arn, table,
                     timeout_s=_budget_s(ctx, _IAM_ROLE_PROPAGATION_BUDGET_S))
    log_group = f"/aws/lambda/{fn}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(logs, log_group))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    esm = lam.create_event_source_mapping(EventSourceArn=src_arn, FunctionName=fn,
                                          BatchSize=1)["UUID"]
    ctx.on_cleanup(lambda: _delete_esm_quiet(lam, esm))
    state = _poll_esm_enabled(lam, esm, timeout_s=_budget_s(ctx, _IAM_ROLE_PROPAGATION_BUDGET_S))
    if state != "Enabled" and _budget_spent(ctx):
        raise TimeoutError("the event source mapping reaching 'Enabled': the run budget ended first; not graded")
    assert state == "Enabled", f"the event source mapping settled at {state!r}, expected 'Enabled'"

    since_ms = int(time.time() * 1000) - 5000
    expected_principal = f"arn:aws:sts::{account}:assumed-role/{role_name}/{fn}"

    sqs.send_message(QueueUrl=src_url, MessageBody=json.dumps({"pk": _ALLOWED_PK, "payload": "alpha"}))
    baseline_item = _poll_item(ctx, ddb, table, _ALLOWED_PK, timeout_s=_budget_s(ctx, _BASELINE_TIMEOUT_S))
    assert baseline_item == {"pk": {"S": _ALLOWED_PK}, "payload": {"S": "alpha"}}, (
        f"the baseline item is {baseline_item!r}, expected the exact attributes that were sent"
    )

    denied = _poll_for_denial(ctx, sqs, logs, src_url, log_group, since_ms,
                              timeout_s=_budget_s(ctx, _DENIAL_TIMEOUT_S))

    assert denied["code"] == _AUTHZ_CODE, (
        f"the denied PutItem reported Error.Code {denied['code']!r}, expected {_AUTHZ_CODE!r} -- "
        "DynamoDB's authz code, not IAM's 'AccessDenied'"
    )
    assert denied["status"] == _AUTHZ_HTTP_STATUS, (
        f"the denial carried HTTP {denied['status']!r}, expected {_AUTHZ_HTTP_STATUS}"
    )
    expected_message = _AUTHZ_MESSAGE.format(principal=expected_principal, table_arn=table_arn)
    assert denied["message"] == expected_message, (
        f"the authz message was\n  {denied['message']!r}\nexpected\n  {expected_message!r}\n"
        "-- the principal must be an assumed-role session whose SESSION NAME is the function name, "
        "and the resource must be the table ARN, not '*'"
    )

    absent = ddb.get_item(TableName=table, Key={"pk": {"S": denied["pk"]}})
    assert "Item" not in absent, (
        f"the denied write LANDED anyway: {absent['Item']!r} -- the authorization failure did not "
        "prevent the effect"
    )
    pks = _scan_pks(ddb, table)
    assert denied["pk"] not in pks, (
        f"the denied key {denied['pk']!r} is present in a full table scan {sorted(pks)!r} -- the "
        "write landed late"
    )

    deliveries = _poll_deliveries(logs, log_group, since_ms, denied["msgid"],
                                  want=_MAX_RECEIVE_COUNT, timeout_s=_budget_s(ctx, _DLQ_LANDING_TIMEOUT_S))
    if len(deliveries) < _MAX_RECEIVE_COUNT and _budget_spent(ctx):
        raise TimeoutError(f"{_MAX_RECEIVE_COUNT} deliveries of the failing message: the run budget ended first; "
                           "not graded")
    assert len(deliveries) == _MAX_RECEIVE_COUNT, (
        f"the failing message was delivered {len(deliveries)} times, expected exactly "
        f"maxReceiveCount={_MAX_RECEIVE_COUNT}: {deliveries!r}"
    )
    assert len({d["rid"] for d in deliveries}) == _MAX_RECEIVE_COUNT, (
        f"the {_MAX_RECEIVE_COUNT} deliveries share a request id: "
        f"{[d['rid'] for d in deliveries]!r} -- they are not distinct invocations"
    )
    assert sorted(d["recv"] for d in deliveries) == ["1", "2"], (
        f"the deliveries reported ApproximateReceiveCount "
        f"{sorted(d['recv'] for d in deliveries)!r}, expected ['1', '2']"
    )

    dlq_msg = _poll_dlq(ctx, sqs, dlq_url, denied["pk"], timeout_s=_budget_s(ctx, _DLQ_LANDING_TIMEOUT_S))
    assert json.loads(dlq_msg["Body"]) == {"pk": denied["pk"], "payload": "probe"}, (
        f"the DLQ body is {dlq_msg['Body']!r}, not the message that was sent"
    )
    assert dlq_msg["Attributes"]["ApproximateReceiveCount"] == _DLQ_RECEIVE_COUNT, (
        f"the DLQ message reports ApproximateReceiveCount "
        f"{dlq_msg['Attributes']['ApproximateReceiveCount']!r}, expected {_DLQ_RECEIVE_COUNT!r} -- "
        f"the {_MAX_RECEIVE_COUNT} source-queue receives must carry over, and this receive is the "
        "next one"
    )
    src_depth = _poll_queue_drained(sqs, src_url, timeout_s=_budget_s(ctx, _DLQ_LANDING_TIMEOUT_S))
    if src_depth != "0" and _budget_spent(ctx):
        raise TimeoutError("the source queue draining after the redrive: the run budget ended first; not graded")
    assert src_depth == "0", (
        f"the source queue still reports {src_depth!r} visible messages after the redrive"
    )

    # Control: the allowed item written first is untouched.
    still_there = ddb.get_item(TableName=table, Key={"pk": {"S": _ALLOWED_PK}})["Item"]
    assert still_there == {"pk": {"S": _ALLOWED_PK}, "payload": {"S": "alpha"}}, (
        f"the allowed item changed to {still_there!r} while the denied message was redriven"
    )

    # Verified inline teardown.
    lam.delete_event_source_mapping(UUID=esm)
    esm_gone = _poll_esm_gone(ctx, lam, esm, timeout_s=_budget_s(ctx, _DLQ_LANDING_TIMEOUT_S))
    assert esm_gone == "ResourceNotFoundException", (
        f"after DeleteEventSourceMapping, GetEventSourceMapping reported {esm_gone!r}"
    )
    lam.delete_function(FunctionName=fn)
    fn_gone = _error_code(lambda: lam.get_function(FunctionName=fn))
    assert fn_gone == "ResourceNotFoundException", (
        f"after DeleteFunction, GetFunction reported {fn_gone!r}"
    )
    logs.delete_log_group(logGroupName=log_group)
    assert not _log_groups_named(logs, log_group), (
        f"the log group {log_group!r} still exists after DeleteLogGroup"
    )
    for url in (src_url, dlq_url):
        sqs.delete_queue(QueueUrl=url)
    for url in (src_url, dlq_url):
        queue_gone = _poll_queue_gone(ctx, sqs, url, timeout_s=_budget_s(ctx, _DLQ_LANDING_TIMEOUT_S))
        assert queue_gone == "AWS.SimpleQueueService.NonExistentQueue", (
            f"after DeleteQueue, GetQueueAttributes on {url!r} reported {queue_gone!r}"
        )
    ddb.delete_table(TableName=table)
    # DeleteTable is asynchronous: DescribeTable reports DELETING for tens of seconds.
    table_gone = _poll_table_gone(ctx, ddb, table, timeout_s=_budget_s(ctx, _DLQ_LANDING_TIMEOUT_S))
    assert table_gone == "ResourceNotFoundException", (
        f"after DeleteTable, DescribeTable reported {table_gone!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("the call succeeded where an error was required")


def _poll_table_gone(ctx, ddb, table, timeout_s):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        except ClientError as err:
            return err.response["Error"]["Code"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("the table disappearing after DeleteTable: the run budget ended first; not graded")
    raise AssertionError(
        f"the table was still describable {timeout_s}s after DeleteTable (status {last!r})"
    )


def _poll_esm_gone(ctx, lam, esm, timeout_s):
    """DeleteEventSourceMapping is asynchronous: GetEventSourceMapping keeps answering with state
    'Deleting' for a while, so poll for the error code rather than reading it once."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = lam.get_event_source_mapping(UUID=esm)["State"]
        except ClientError as err:
            return err.response["Error"]["Code"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("the event source mapping disappearing after DeleteEventSourceMapping: the run budget ended first; not graded")
    raise AssertionError(
        f"the event source mapping was still readable {timeout_s}s after "
        f"DeleteEventSourceMapping (state {last!r})"
    )


def _poll_queue_gone(ctx, sqs, url, timeout_s):
    """DeleteQueue propagation is documented to take up to ~60s on real AWS, so poll for the
    NonExistentQueue error rather than reading it once."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])
            last = "still describable"
        except ClientError as err:
            return err.response["Error"]["Code"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"the queue {url!r} disappearing after DeleteQueue: the run budget ended first; not graded")
    raise AssertionError(
        f"the queue {url!r} was still describable {timeout_s}s after DeleteQueue (last {last!r})"
    )


def _delete_role_policy_quiet(iam, role_name, policy):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_log_group_quiet(logs, log_group):
    from botocore.exceptions import ClientError

    try:
        logs.delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_table_quiet(ddb, table):
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_queue_quiet(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("AWS.SimpleQueueService.NonExistentQueue",
                                                 "QueueDoesNotExist"):
            raise


def _delete_esm_quiet(lam, esm):
    from botocore.exceptions import ClientError

    try:
        lam.delete_event_source_mapping(UUID=esm)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _zip_handler():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("handler.py", date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        archive.writestr(info, _HANDLER)
    return buf.getvalue()


def _create_function(ctx, lam, fn, role_arn, table, timeout_s):
    """CreateFunction, retrying the IAM role-propagation window Lambda reports as
    InvalidParameterValueException."""
    from botocore.exceptions import ClientError

    payload = _zip_handler()
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=fn, Runtime=_RUNTIME, Role=role_arn, Handler="handler.handler",
                Code={"ZipFile": payload}, Timeout=_FN_TIMEOUT_S, MemorySize=256,
                Environment={"Variables": {"TABLE": table}},
                Tags={"sim2real": "g1-fault-injection"})
            ctx.on_cleanup(lambda: _delete_function_quiet(lam, fn))
            return
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last != "InvalidParameterValueException":
                raise
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("CreateFunction succeeding past IAM role propagation: the run budget ended first; not graded")
    raise AssertionError(f"CreateFunction never succeeded in {timeout_s}s (last {last!r})")


def _delete_function_quiet(lam, fn):
    from botocore.exceptions import ClientError

    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_esm_enabled(lam, esm, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_event_source_mapping(UUID=esm)["State"]
        if last == "Enabled":
            return last
        time.sleep(2)
    return last


def _poll_item(ctx, ddb, table, pk, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = ddb.get_item(TableName=table, Key={"pk": {"S": pk}})
        if "Item" in got:
            return got["Item"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"item {pk!r} appearing in {table!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"item {pk!r} never appeared in {table!r} within {timeout_s}s -- the SQS -> Lambda -> "
        "DynamoDB path never worked, so nothing below can be attributed to the key condition"
    )


def _scan_pks(ddb, table):
    pks = set()
    for page in ddb.get_paginator("scan").paginate(TableName=table,
                                                   ProjectionExpression="pk"):
        pks.update(item["pk"]["S"] for item in page["Items"])
    return pks


def _log_lines(logs, log_group, since_ms, marker):
    from botocore.exceptions import ClientError

    out = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=log_group, startTime=since_ms, filterPattern=f'"{marker}"'):
            out.extend(page.get("events", []))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    parsed = []
    for event in out:
        text = event["message"]
        at = text.find(marker)
        if at < 0:
            continue
        try:
            parsed.append(json.loads(text[at + len(marker):].strip()))
        except ValueError:
            continue
    return parsed


def _poll_for_denial(ctx, sqs, logs, src_url, log_group, since_ms, timeout_s):
    """Send one message whose key the role does not allow and return its denial log line."""
    pk = "P1"
    sqs.send_message(QueueUrl=src_url, MessageBody=json.dumps({"pk": pk, "payload": "probe"}))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        failures = [line for line in _log_lines(logs, log_group, since_ms, _FAIL_MARKER)
                    if line["pk"] == pk]
        if failures:
            return failures[0]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("the disallowed key's write being denied: the run budget ended first; not graded")
    raise AssertionError(
        f"no denial was logged for key {pk!r} within {timeout_s}s -- a PutItem outside the "
        "dynamodb:LeadingKeys condition was not refused"
    )


def _poll_deliveries(logs, log_group, since_ms, msgid, want, timeout_s):
    deadline = time.monotonic() + timeout_s
    matching = []
    while time.monotonic() < deadline:
        matching = [line for line in _log_lines(logs, log_group, since_ms, _FAIL_MARKER)
                    if line["msgid"] == msgid]
        if len(matching) >= want:
            return matching
        time.sleep(2)
    return matching


def _poll_dlq(ctx, sqs, dlq_url, want_pk, timeout_s):
    """The dead-lettered message whose body carries ``want_pk``.

    Each message is received from the DLQ exactly ONCE (a long VisibilityTimeout keeps it out of a
    later iteration), which is what makes its ApproximateReceiveCount assertable.
    """
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        got = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
                                  AttributeNames=["All"], VisibilityTimeout=300)
        for message in got.get("Messages", []):
            seen.append(message["Body"])
            if json.loads(message["Body"]).get("pk") == want_pk:
                return message
    if _budget_spent(ctx):
        raise TimeoutError(f"the message for key {want_pk!r} reaching the dead-letter queue: the run budget ended first; not graded")
    raise AssertionError(
        f"no message for key {want_pk!r} reached the dead-letter queue within {timeout_s}s "
        f"(the DLQ yielded {seen!r}) -- the redrive policy's maxReceiveCount was never enforced"
    )


def _poll_queue_drained(sqs, queue_url, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"]
        if last == "0":
            return last
        time.sleep(2)
    return last


def _log_groups_named(logs, log_group):
    found = []
    for page in logs.get_paginator("describe_log_groups").paginate(
            logGroupNamePrefix=log_group):
        found.extend(g["logGroupName"] for g in page["logGroups"] if g["logGroupName"] == log_group)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
