"""eventbridge-rule-input-path-extracts-distribution-id."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-input-path-extracts-distribution-id"
GROUP = "data-format"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule target's InputPath extracts only the distribution ID field from a
    CloudFront event, invoking the target with that scalar value instead of the
    full event envelope.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    obs_queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-obs-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=obs_queue_url))
    obs_queue_arn = sqs.get_queue_attributes(QueueUrl=obs_queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    code = f"""
import json
import boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    _sqs.send_message(QueueUrl={obs_queue_url!r}, MessageBody=json.dumps(event))
    return event
"""
    role_arn = _create_lambda_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": obs_queue_arn}]
    )
    fn_name = ctx.unique_name("sim2real-fwd-")
    fn_arn = _create_lambda_function(ctx, fn_name, role_arn, code)
    _warm_up_role(ctx, fn_name, obs_queue_url)

    dist_id = "E" + uuid.uuid4().hex[:13].upper()
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {
        "source": ["sim2real.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventName": ["CreateInvalidation"],
            "requestParameters": {"distributionId": [dist_id]},
        },
    }
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _allow_eventbridge_invoke(ctx, fn_name, rule_arn)

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "target-1",
                "Arn": fn_arn,
                "InputPath": "$.detail.requestParameters.distributionId",
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(
                    {
                        "eventName": "CreateInvalidation",
                        "requestParameters": {
                            "distributionId": dist_id,
                            "invalidationBatch": {"callerReference": "sim2real"},
                        },
                        "responseElements": {"invalidation": {"id": "IABC123EXAMPLE"}},
                    }
                ),
            }
        ]
    )

    msg = _poll_for_message(ctx, obs_queue_url, timeout_s=90)
    payload = json.loads(msg["Body"])
    assert payload == dist_id, f"expected InputPath to extract just the distribution id, got {payload!r}"


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, name: str, role_arn: str, code: str) -> str:
    lam = ctx.client("lambda")
    zbytes = _zip_code(code)
    deadline = time.monotonic() + 30
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zbytes},
                Timeout=15,
                MemorySize=128,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda creation never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_lambda_active(ctx, name)
    return resp["FunctionArn"]


def _wait_lambda_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda {name} never became Active")


def _allow_eventbridge_invoke(ctx, function_name: str, rule_arn: str, statement_id: str = "AllowEventBridge") -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _warm_up_role(ctx, fn_name: str, obs_queue_url: str, timeout_s: float = 60) -> None:
    """IAM role permissions attached just before function creation can lag behind
    for a few seconds; invoke directly (retrying on the function's own AccessDenied)
    until the role's sqs:SendMessage permission has propagated, then drain the
    warm-up message(s) so they don't contaminate the real assertions."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=fn_name, Payload=b'{"warmup": true}', InvocationType="RequestResponse")
        if resp.get("FunctionError"):
            last_err = resp["Payload"].read()
            time.sleep(3)
            continue
        break
    else:
        raise AssertionError(f"lambda role permissions never propagated: {last_err}")
    drain_deadline = time.monotonic() + 10
    while time.monotonic() < drain_deadline:
        r = sqs.receive_message(QueueUrl=obs_queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = r.get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=obs_queue_url, ReceiptHandle=m["ReceiptHandle"])


def _poll_for_message(ctx, queue_url: str, timeout_s: float = 90):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]
        time.sleep(1)
    raise AssertionError(f"no message received on {queue_url} within {timeout_s}s")


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
