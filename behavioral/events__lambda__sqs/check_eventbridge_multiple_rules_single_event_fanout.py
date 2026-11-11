"""eventbridge-multiple-rules-single-event-fanout."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-multiple-rules-single-event-fanout"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """One PutEvents entry matching two rules reaches both targets, a Lambda via one rule and an
    SQS queue via the other, each with the event's marker and source."""
    result_queue = _create_queue(ctx)  # observability sink for the Lambda invocation
    sqs_target_queue = _create_queue_with_events_policy(ctx)  # direct EventBridge target

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

    pattern = {"source": ["sim2real.fanout"], "detail-type": ["FanoutTest"]}

    rule_lambda = _put_rule(ctx, pattern=pattern)
    _add_lambda_permission_for_rule(ctx, fn["name"], rule_lambda["arn"])
    _put_targets(ctx, rule_lambda["name"], [{"Id": "lambda-target", "Arn": fn["arn"]}])

    rule_sqs = _put_rule(ctx, pattern=pattern)
    _put_targets(
        ctx,
        rule_sqs["name"],
        [{"Id": "sqs-target", "Arn": sqs_target_queue["arn"]}],
    )

    delivered = _emit_until_delivered(
        ctx,
        {
            "Source": "sim2real.fanout",
            "DetailType": "FanoutTest",
            "Detail": json.dumps({"marker": "fanout-once"}),
        },
        [result_queue["url"], sqs_target_queue["url"]],
    )

    lambda_event = json.loads(delivered[result_queue["url"]][0]["Body"])
    assert lambda_event["detail"]["marker"] == "fanout-once", (
        f"lambda-routed message had detail {lambda_event['detail']!r}, expected marker fanout-once"
    )
    assert lambda_event["source"] == "sim2real.fanout", (
        f"lambda-routed message had source {lambda_event['source']!r}, expected sim2real.fanout"
    )

    sqs_event = json.loads(delivered[sqs_target_queue["url"]][0]["Body"])
    assert sqs_event["detail"]["marker"] == "fanout-once", (
        f"sqs-direct message had detail {sqs_event['detail']!r}, expected marker fanout-once"
    )
    assert sqs_event["source"] == "sim2real.fanout", (
        f"sqs-direct message had source {sqs_event['source']!r}, expected sim2real.fanout"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        Tags={"sim2real:managed": "true"},
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


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _create_queue_with_events_policy(ctx) -> dict[str, str]:
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    account_id = queue["arn"].split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account_id}:rule/*"
                    }
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    return queue


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


def _emit_until_delivered(ctx, entry, queue_urls, attempts=15, wait_s=3):
    """Re-emit ``entry`` until every queue in ``queue_urls`` has received at least one message.
    A single PutEvents call can land before a freshly created rule/target pair is fully
    effective and be silently dropped, so this re-sends the identical event rather than betting
    the whole check on one delivery attempt."""
    events = ctx.client("events")
    delivered: dict[str, list] = {}
    for _ in range(attempts):
        events.put_events(Entries=[entry])
        for url in queue_urls:
            if url in delivered:
                continue
            msgs = _drain_queue(ctx, url, wait_s=wait_s)
            if msgs:
                delivered[url] = msgs
        if len(delivered) == len(queue_urls):
            return delivered
    missing = [u for u in queue_urls if u not in delivered]
    raise AssertionError(f"event never delivered to: {missing} after {attempts} attempts")


def _put_rule(ctx, pattern=None, schedule=None, state="ENABLED", event_bus_name=None):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-ebl-rule-")
    kwargs: dict[str, Any] = {
        "Name": name,
        "State": state,
        "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
    }
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
