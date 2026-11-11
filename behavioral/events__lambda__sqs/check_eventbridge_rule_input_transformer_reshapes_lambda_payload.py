"""eventbridge-rule-input-transformer-reshapes-lambda-payload."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-input-transformer-reshapes-lambda-payload"
GROUP = "data-format"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge InputTransformer reshapes the matched event before it reaches the Lambda
    target's invocation payload (the Lambda receives the transformed object directly, not the
    standard PutEvents envelope)."""
    result_queue = _create_queue(ctx)
    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sqs:SendMessage",
                    "Resource": result_queue["arn"],
                }
            ],
        },
    )
    fn = _create_lambda_function(
        ctx,
        role_arn,
        source=(
            "import json, os, boto3\n"
            "sqs = boto3.client('sqs')\n"
            "def handler(event, context):\n"
            "    sqs.send_message(QueueUrl=os.environ['RESULT_QUEUE_URL'], MessageBody=json.dumps(event))\n"
            "    return {'ok': True}\n"
        ),
        env={"RESULT_QUEUE_URL": result_queue["url"]},
    )

    rule = _put_rule(
        ctx,
        pattern={"source": ["sim2real.orders"], "detail-type": ["OrderPlaced"]},
    )
    _add_lambda_permission_for_rule(ctx, fn["name"], rule["arn"])
    _put_targets(
        ctx,
        rule["name"],
        [
            {
                "Id": "lambda-target",
                "Arn": fn["arn"],
                "InputTransformer": {
                    "InputPathsMap": {
                        "oid": "$.detail.orderId",
                        "amt": "$.detail.amount",
                    },
                    "InputTemplate": (
                        '{"orderId": <oid>, "amount": <amt>, '
                        '"note": "transformed-by-eventbridge"}'
                    ),
                },
            }
        ],
    )

    # A freshly created rule/target is not always immediately effective, and EventBridge
    # silently drops an event published before delivery is live — re-emit until the
    # transformed payload lands rather than betting on one PutEvents.
    messages = _emit_until_delivered(
        ctx,
        {
            "Source": "sim2real.orders",
            "DetailType": "OrderPlaced",
            "Detail": json.dumps({"orderId": "abc-123", "amount": "42"}),
        },
        result_queue["url"],
    )
    assert len(messages) >= 1
    payload = json.loads(messages[0]["Body"])
    assert payload == {
        "orderId": "abc-123",
        "amount": "42",
        "note": "transformed-by-eventbridge",
    }, payload


_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:check": CHECK}


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _managed_tags().items()]


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _lambda_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_lambda_role(ctx, inline_policy=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebl-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_lambda_trust_policy(),
        Tags=_managed_tags_kv(),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )
    if inline_policy:
        policy_name = ctx.unique_name("sim2real-ebl-policy-")
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _zip_code(source: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_lambda_function(
    ctx, role_arn, source, handler="index.handler", env=None, timeout=15
) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-ebl-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _zip_code(source)},
        Timeout=timeout,
        Publish=True,
        Tags=_managed_tags(),
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    resp = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, policy=None, attrs=None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-q-")
    attributes = dict(attrs or {})
    if policy:
        attributes["Policy"] = json.dumps(policy)
    kwargs: dict[str, Any] = {"QueueName": name, "tags": _managed_tags()}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url, max_messages=10, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _collect_messages(ctx, queue_url, expected_count=1, timeout_s=60.0):
    """Drain the queue until expected_count messages arrive or timeout_s passes; return what arrived."""
    deadline = time.monotonic() + timeout_s
    out = []
    while time.monotonic() < deadline and len(out) < expected_count:
        out.extend(_drain_queue(ctx, queue_url, wait_s=5))
    return out


def _emit_until_delivered(ctx, entry, queue_url, attempts=15, per_attempt_timeout_s=6.0):
    events = ctx.client("events")
    for _ in range(attempts):
        events.put_events(Entries=[entry])
        messages = _collect_messages(
            ctx, queue_url, expected_count=1, timeout_s=per_attempt_timeout_s
        )
        if messages:
            return messages
    raise AssertionError(
        f"event never delivered after {attempts} attempts "
        f"(~{attempts * per_attempt_timeout_s:.0f}s)"
    )


def _put_rule(ctx, pattern=None, schedule=None, state="ENABLED", event_bus_name=None):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-ebl-rule-")
    kwargs: dict[str, Any] = {"Name": name, "State": state, "Tags": _managed_tags_kv()}
    if pattern is not None:
        kwargs["EventPattern"] = json.dumps(pattern)
    if schedule is not None:
        kwargs["ScheduleExpression"] = schedule
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_rule(**kwargs)
    if event_bus_name:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=event_bus_name))
    else:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_targets(ctx, rule_name, targets, event_bus_name=None):
    events = ctx.client("events")
    kwargs: dict[str, Any] = {"Rule": rule_name, "Targets": targets}
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_targets(**kwargs)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failures: {resp['FailedEntries']}")
    ids = [t["Id"] for t in targets]

    def _cleanup():
        kw: dict[str, Any] = {"Rule": rule_name, "Ids": ids}
        if event_bus_name:
            kw["EventBusName"] = event_bus_name
        events.remove_targets(**kw)

    ctx.on_cleanup(_cleanup)


def _add_lambda_permission_for_rule(ctx, function_name, rule_arn, statement_id=None):
    lam = ctx.client("lambda")
    sid = statement_id or ctx.unique_name("sim2real-ebl-perm-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=sid))


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
