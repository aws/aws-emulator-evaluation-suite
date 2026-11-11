"""eventbridge-rule-missing-target-permission-blocks-backup-event-delivery."""
from __future__ import annotations

import io
import json
import textwrap
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-missing-target-permission-blocks-backup-event-delivery"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda target without a resource-based permission for the rule's ARN is not invoked by a
    matching Backup-shaped event on a custom source, and the same function is invoked once the
    permission is added."""
    events = ctx.client("events")
    lam = ctx.client("lambda")

    forward_queue = _create_plain_queue(ctx)
    func_name, func_arn = _create_forwarder_lambda(ctx, forward_queue["url"], forward_queue["arn"])

    backup_source = "sim2real.backup"
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": [backup_source], "detail-type": ["Backup Job State Change"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": func_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    # No lambda:AddPermission has been granted yet -- EventBridge cannot invoke the function.
    blocked_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": blocked_marker, "state": "COMPLETED"}),
            }
        ]
    )
    _assert_no_message_matching(
        ctx, forward_queue["url"], lambda evt: _job_id_in(evt, blocked_marker), duration_s=25.0
    )

    lam.add_permission(
        FunctionName=func_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    allowed_marker = str(uuid.uuid4())
    events.put_events(
        Entries=[
            {
                "Source": backup_source,
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": allowed_marker, "state": "COMPLETED"}),
            }
        ]
    )
    forwarded = _wait_for_event_matching(
        ctx, forward_queue["url"], lambda evt: _job_id_in(evt, allowed_marker), timeout_s=90.0, interval_s=5.0
    )
    assert forwarded["detail"]["backupJobId"] == allowed_marker


def _job_id_in(evt: dict[str, Any], marker: str) -> bool:
    detail = evt.get("detail", evt) if isinstance(evt, dict) else {}
    return detail.get("backupJobId") == marker


_FORWARDER_CODE = textwrap.dedent(
    """
    import json
    import os
    import boto3

    def handler(event, context):
        sqs = boto3.client("sqs")
        sqs.send_message(QueueUrl=os.environ["FORWARD_QUEUE_URL"], MessageBody=json.dumps(event))
        return {"forwarded": True}
    """
)


def _lambda_zip_bytes(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_body)
    return buf.getvalue()


def _create_forwarder_lambda(ctx, queue_url: str, queue_arn: str) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="forward-sqs",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="forward-sqs"))

    func_name = ctx.unique_name("sim2real-fwd-")
    zip_bytes = _lambda_zip_bytes(_FORWARDER_CODE)

    deadline = time.monotonic() + 90.0
    last_exc: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"FORWARD_QUEUE_URL": queue_url}},
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            # IAM is eventually consistent -- retry until the freshly created role is assumable.
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    if resp is None:
        raise AssertionError(f"CreateFunction never succeeded within 90s: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))

    def _probe():
        return lam.get_function(FunctionName=func_name)["Configuration"]["State"]

    _poll_until(_probe, lambda s: s == "Active", timeout_s=60.0, interval_s=2.0, description="lambda Active")
    return func_name, resp["FunctionArn"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_plain_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-fwdq-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _wait_for_event_matching(
    ctx, queue_url: str, match_fn, timeout_s: float = 90.0, interval_s: float = 3.0
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                return body
        time.sleep(max(0.0, interval_s - 10.0))
    raise AssertionError(f"no matching event arrived on {queue_url} within {timeout_s}s")


def _assert_no_message_matching(ctx, queue_url: str, match_fn, duration_s: float = 20.0) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if match_fn(body):
                raise AssertionError(f"unpermitted target invocation was unexpectedly observed: {body}")


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
