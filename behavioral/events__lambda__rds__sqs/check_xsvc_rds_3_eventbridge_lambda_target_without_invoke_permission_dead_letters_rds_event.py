"""xsvc-rds-3-eventbridge-lambda-target-without-invoke-permission-dead-letters-rds-event."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-rds-3-eventbridge-lambda-target-without-invoke-permission-dead-letters-rds-event"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "rds", "sqs"]

_DETAIL_TYPE = "AWS API Call via CloudTrail"
# Without a logging CloudTrail trail, ModifyDBParameterGroup emits no aws.rds event at all (RDS has
# no native event for an unattached parameter group); with one, the event arrives within seconds.
_DELIVERY_TIMEOUT_S = 240
_RETRIGGER_EVERY_S = 20
# A permission failure is dead-lettered without retry despite MaximumRetryAttempts=2, and the DLQ
# body is the original event; EventBridge adds no event-id attribute.
_EXPECTED_ERROR_CODE = "NO_PERMISSIONS"
_RETRY_POLICY = {"MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 300}


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A Lambda target without an events.amazonaws.com invoke permission dead-letters the aws.rds
    ModifyDBParameterGroup event with NO_PERMISSIONS and never runs; granting it lets it deliver.
    """
    _log_groups_for(ctx)  # registered first, so its reap runs last
    rds = ctx.client("rds")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    _create_trail(ctx, account)

    sink = _create_queue(ctx)
    dlq = _create_queue(ctx)
    role = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]}],
    )
    fn = _create_function(ctx, _SINK_CODE, role, {"SINK_URL": sink["url"]})

    pg = _xname(ctx, "pg")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg, DBParameterGroupFamily="mysql8.0",
        Description="sim2real-xsvc eventbridge permission check",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg))

    rule = _xname(ctx, "rule")
    pattern = {
        "source": ["aws.rds"],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"eventSource": ["rds.amazonaws.com"], "eventName": ["ModifyDBParameterGroup"],
                   "requestParameters": {"dBParameterGroupName": [pg]}},
    }
    rule_arn = events.put_rule(Name=rule, EventPattern=json.dumps(pattern),
                               Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule))
    sqs.set_queue_attributes(QueueUrl=dlq["url"], Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": dlq["arn"],
                       "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    # Deliberately NO lambda add_permission: EventBridge cannot invoke the target.
    events.put_targets(Rule=rule, Targets=[{
        "Id": "fn", "Arn": fn["arn"], "DeadLetterConfig": {"Arn": dlq["arn"]},
        "RetryPolicy": dict(_RETRY_POLICY)}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["fn"]))

    denied_ids: list = []
    dead = _trigger_until(ctx, pg, denied_ids, dlq["url"],
                          description="the denied RDS event reaching the target DLQ")
    attrs = {k: v.get("StringValue") for k, v in (dead.get("MessageAttributes") or {}).items()}
    print(f"[observed] DLQ attributes {attrs!r}")
    assert attrs.get("ERROR_CODE") == _EXPECTED_ERROR_CODE, (
        f"ERROR_CODE is {attrs.get('ERROR_CODE')!r}, expected {_EXPECTED_ERROR_CODE!r}; "
        f"attrs {attrs!r}"
    )
    message = attrs.get("ERROR_MESSAGE") or ""
    assert "lambda:InvokeFunction" in message and fn["arn"] in message, (
        f"ERROR_MESSAGE does not name the denied lambda:InvokeFunction on {fn['arn']!r}: "
        f"{message!r}"
    )
    assert attrs.get("RULE_ARN") == rule_arn, (
        f"RULE_ARN is {attrs.get('RULE_ARN')!r}, expected {rule_arn!r}"
    )
    assert attrs.get("TARGET_ARN") == fn["arn"], (
        f"TARGET_ARN is {attrs.get('TARGET_ARN')!r}, expected {fn['arn']!r}"
    )
    # EventBridge adds RETRY_ATTEMPTS / EXHAUSTED_RETRY_CONDITION only to an event it retried;
    # their absence is the observable proof that this permission failure was not retried.
    assert set(attrs) == {"ERROR_CODE", "ERROR_MESSAGE", "RULE_ARN", "TARGET_ARN"}, (
        f"DLQ attribute set {sorted(attrs)!r}; a non-retried NO_PERMISSIONS dead-letter carries "
        f"exactly ERROR_CODE, ERROR_MESSAGE, RULE_ARN, TARGET_ARN"
    )
    body = json.loads(dead["Body"])
    assert body.get("source") == "aws.rds" and body.get("detail-type") == _DETAIL_TYPE, (
        f"DLQ body is not the routed aws.rds event: {dead['Body'][:400]!r}"
    )
    detail = body.get("detail") or {}
    assert detail.get("eventName") == "ModifyDBParameterGroup", (
        f"DLQ event names {detail.get('eventName')!r}, expected 'ModifyDBParameterGroup'"
    )
    assert (detail.get("requestParameters") or {}).get("dBParameterGroupName") == pg, (
        f"DLQ event is for parameter group {detail.get('requestParameters')!r}, not {pg!r}"
    )
    assert detail.get("requestID") in denied_ids, (
        f"DLQ event requestID {detail.get('requestID')!r} is none of the RequestIds RDS returned "
        f"for this check's calls {denied_ids!r}"
    )
    dead_event_id = body.get("id")
    assert isinstance(dead_event_id, str) and len(dead_event_id) == 36, (
        f"DLQ body carries no source event id: {dead_event_id!r}"
    )

    # Effect absent at the real destination: the function never ran.
    leaked = _drain(ctx, sink["url"], window_s=10.0)
    assert not leaked, (
        "the Lambda target RAN without lambda:InvokeFunction for events.amazonaws.com -- the "
        f"resource policy was not enforced; sink saw {[m['Body'][:200] for m in leaked]!r}"
    )

    # Positive control: grant exactly the withheld permission on the same rule and target.
    lam.add_permission(
        FunctionName=fn["name"], StatementId="allow-eventbridge-rule",
        Action="lambda:InvokeFunction", Principal="events.amazonaws.com", SourceArn=rule_arn,
    )
    granted_ids: list = []
    got = _trigger_until(ctx, pg, granted_ids, sink["url"],
                         description="the permitted RDS event invoking the same target",
                         accept=lambda m: (json.loads(m["Body"])["event"].get("detail") or {})
                         .get("requestID") in granted_ids)
    invoked = json.loads(got["Body"])["event"]
    assert invoked.get("source") == "aws.rds", f"function received {invoked!r}"
    assert (invoked.get("detail") or {}).get("eventName") == "ModifyDBParameterGroup", (
        f"function received event {invoked.get('detail', {}).get('eventName')!r}"
    )
    assert invoked.get("id") != dead_event_id, (
        f"the invoking event reused the dead-lettered event id {dead_event_id!r}"
    )


_SINK_CODE = """
import json, os, boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(QueueUrl=os.environ["SINK_URL"], MessageBody=json.dumps({"event": event}))
    return {"ok": True}
"""


def _trigger_until(ctx, pg: str, request_ids: list, url: str, *, description: str,
                   accept=None) -> dict:
    """Issue a real ModifyDBParameterGroup every _RETRIGGER_EVERY_S (recording each RequestId)
    until a matching message lands on `url`. Re-triggering covers the trail's start-up and the
    resource-policy propagation window, neither of which exposes a condition to poll."""
    rds = ctx.client("rds")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_fire = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_fire:
            resp = rds.modify_db_parameter_group(
                DBParameterGroupName=pg,
                Parameters=[{"ParameterName": "max_connect_errors",
                             "ParameterValue": str(100 + len(request_ids)),
                             "ApplyMethod": "immediate"}])
            request_ids.append(resp["ResponseMetadata"]["RequestId"])
            next_fire = time.monotonic() + _RETRIGGER_EVERY_S
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            if accept is None or accept(m):
                return m
    raise AssertionError(
        f"{description}: nothing arrived within {_DELIVERY_TIMEOUT_S}s after "
        f"{len(request_ids)} ModifyDBParameterGroup calls"
    )


_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true"}
_ROLE_PROPAGATION_S = 90
_LOG_REAP_BOUND_S = 40
_LOG_QUIET_S = 20
_LOG_GROUPS: dict = {}


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_trail(ctx, account: str) -> None:
    """A single-region trail logging to a bucket this check owns. Bucket teardown is registered
    first so LIFO runs it after the trail is gone; it re-empties in a loop because CloudTrail can
    flush a final log file after StopLogging."""
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    bucket = _xname(ctx, "ct").lower()[:63]
    trail = _xname(ctx, "trail")
    kwargs = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{trail}"
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}",
         "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
         "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
         "Condition": {"StringEquals": {"aws:SourceArn": trail_arn,
                                        "s3:x-amz-acl": "bucket-owner-full-control"}}}]}))
    deadline = time.monotonic() + 60
    while True:
        try:
            ct.create_trail(Name=trail, S3BucketName=bucket, IsMultiRegionTrail=False,
                            IncludeGlobalServiceEvents=False,
                            TagsList=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InsufficientS3BucketPolicyException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail))
    ct.start_logging(Name=trail)
    ctx.on_cleanup(lambda: ct.stop_logging(Name=trail))


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty":
                raise
            time.sleep(3)
    raise RuntimeError(f"trail bucket {bucket!r} did not empty within 60s")


def _create_queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx, service: str, statements: list) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if service == "lambda.amazonaws.com":
        statements = statements + [{"Effect": "Allow", "Action": [
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*"}]
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    return arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pname)
    iam.delete_role(RoleName=name)


def _log_groups_for(ctx) -> list:
    """The ONE log-group cleanup for this run, registered first so LIFO runs it LAST."""
    key = id(ctx)
    if key not in _LOG_GROUPS:
        groups: list = []
        _LOG_GROUPS[key] = groups
        ctx.on_cleanup(lambda: _reap_log_groups(ctx, _LOG_GROUPS.pop(key, groups)))
    return _LOG_GROUPS[key]


def _reap_log_groups(ctx, groups: list) -> None:
    """Delete each /aws/lambda/<fn> until all have stayed absent for a quiet window: a buffered
    log stream can flush after DeleteFunction and recreate the group."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + _LOG_REAP_BOUND_S
    absent_since = None
    while time.monotonic() < deadline:
        present = False
        for group in groups:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if any(g["logGroupName"] == group for g in found):
                present = True
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                        raise
        if present:
            absent_since = None
        elif absent_since is None:
            absent_since = time.monotonic()
        elif time.monotonic() - absent_since >= _LOG_QUIET_S:
            return
        time.sleep(4)
    raise RuntimeError(
        f"log groups {groups!r} did not stay deleted within {_LOG_REAP_BOUND_S}s"
    )


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_function(ctx, code: str, role_arn: str, env: dict) -> dict:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    _log_groups_for(ctx).append(f"/aws/lambda/{name}")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip(code)}, Timeout=30, MemorySize=128,
                Environment={"Variables": env}, Tags=dict(_TAGS),
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException" \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_function(ctx, name))
    deadline = time.monotonic() + 90
    while lam.get_function_configuration(FunctionName=name).get("State") != "Active":
        assert time.monotonic() < deadline, f"function {name} never became Active"
        time.sleep(2)
    return {"name": name, "arn": arn}


def _delete_function(ctx, name: str) -> None:
    try:
        ctx.client("lambda").delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _drain(ctx, url: str, *, window_s: float) -> list:
    """Receive-and-delete everything visible for a bounded window."""
    sqs = ctx.client("sqs")
    out: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = int(max(1, min(5, deadline - time.monotonic())))
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            out.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
