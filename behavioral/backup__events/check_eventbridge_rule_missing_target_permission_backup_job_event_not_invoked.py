"""eventbridge-rule-missing-target-permission-backup-job-event-not-invoked."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-missing-target-permission-backup-job-event-not-invoked"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Backup-job-shaped event matching a rule is not delivered to a Lambda target without an invoke
    permission for that rule, and is delivered once the permission is granted. The event uses a
    non-"aws." source, since PutEvents drops entries in the reserved "aws." namespace."""
    backup_source = "sim2real.backup"
    queue_url, queue_arn = _create_marker_queue(ctx)
    function_name, function_arn = _create_marker_lambda(ctx, queue_url)
    _rule_name, rule_arn = _create_rule_with_lambda_target(
        ctx,
        pattern={"source": [backup_source], "detail-type": ["Backup Job State Change"], "detail": {"state": ["COMPLETED"]}},
        function_arn=function_arn,
    )

    events = ctx.client("events")

    missing_perm_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": missing_perm_marker, "state": "COMPLETED"}),
            }
        ]
    )
    not_invoked = _wait_for_message(
        ctx, queue_url, predicate=lambda body: body.get("marker") == missing_perm_marker, timeout_s=90.0
    )
    assert not_invoked is None, "Lambda was invoked despite lacking a resource policy permitting this rule"

    lambda_client = ctx.client("lambda")
    lambda_client.add_permission(
        FunctionName=function_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    # The Lambda resource-policy permission just granted needs a moment to
    # propagate before EventBridge's invoke actually succeeds -- retry the
    # PutEvents+observe round trip (fresh marker each attempt) instead of a
    # single fire-and-wait.
    invoked = None
    retry_deadline = time.monotonic() + 120.0
    while invoked is None and time.monotonic() < retry_deadline:
        granted_marker = str(uuid.uuid4())
        events.put_events(
            Entries=[
                {
                    "Source": backup_source,
                    "DetailType": "Backup Job State Change",
                    "Detail": json.dumps({"backupJobId": granted_marker, "state": "COMPLETED"}),
                }
            ]
        )
        invoked = _wait_for_message(
            ctx, queue_url, predicate=lambda body: body.get("marker") == granted_marker, timeout_s=30.0
        )
    assert invoked is not None, "positive control: Lambda was not invoked even after granting the invoke permission"
    assert invoked["marker"] == granted_marker, (
        f"expected the forwarded marker to be the latest attempt's {granted_marker!r}, got {invoked['marker']!r}"
    )


def _create_marker_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-invokeq-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_marker_lambda(ctx, queue_url: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")
    sqs = ctx.client("sqs")

    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    inline_policy_name = "sim2real-send-marker"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
            }
        ),
    )

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    code = (
        "import json, os, boto3\n"
        "def handler(event, context):\n"
        "    marker = (event.get('detail') or {}).get('backupJobId', '')\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps({'marker': marker}))\n"
        "    return {'ok': True}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", code)

    function_name = ctx.unique_name("sim2real-backup-evt-fn-")

    def _create():
        ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
        return lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": buf.getvalue()},
            Environment={"Variables": {"QUEUE_URL": queue_url}},
            Timeout=30,
        )

    created = _retry_until_success(_create, retry_codes={"InvalidParameterValueException"}, timeout_s=90.0)
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=function_name))
    lambda_client.get_waiter("function_active").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return function_name, created["FunctionArn"]


def _create_rule_with_lambda_target(ctx, pattern: dict, function_arn: str) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    rule = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    target_id = "target-1"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": function_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))
    return rule_name, rule_arn


def _retry_until_success(fn: Callable[[], Any], retry_codes: set[str], timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _wait_for_message(ctx, queue_url: str, predicate: Callable[[dict], bool], timeout_s: float = 90.0) -> dict | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except ValueError:
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body is not None and predicate(body):
                return body
    return None


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
