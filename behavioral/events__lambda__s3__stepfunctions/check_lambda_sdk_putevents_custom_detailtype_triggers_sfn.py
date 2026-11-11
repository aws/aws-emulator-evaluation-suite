"""lambda-sdk-putevents-custom-detailtype-triggers-sfn."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-putevents-custom-detailtype-triggers-sfn"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]

_HANDLER_SRC = """
import json, os, boto3

def handler(event, context):
    eb = boto3.client('events')
    resp = eb.put_events(Entries=[{
        'Source': 'sim2real.workflow',
        'DetailType': event['detail_type'],
        'Detail': json.dumps(event.get('detail', {})),
        'EventBusName': os.environ.get('BUS_NAME', 'default'),
    }])
    return {
        'FailedEntryCount': resp['FailedEntryCount'],
        'EventId': resp['Entries'][0].get('EventId'),
    }
"""

_PASS_DEFINITION = {
    "Comment": "sim2real pass-through, started by EventBridge",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "End": True}},
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom detail-type event put from a Lambda handler matches the rule and starts a Step
    Functions execution whose input carries the event's marker, detail-type and source, and that
    execution reaches SUCCEEDED."""
    sfn = ctx.client("stepfunctions")
    detail_type = "sim2real-workflow-trigger"

    sm_role_arn = _create_sfn_role(ctx)
    sm_arn, sm_name = _create_state_machine(ctx, sm_role_arn, _PASS_DEFINITION)

    _put_rule_with_sfn_target(
        ctx, {"source": ["sim2real.workflow"], "detail-type": [detail_type]}, sm_arn
    )

    lambda_role_arn = _create_lambda_role(
        ctx,
        inline_policies={
            "put-events": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
            }
        },
    )
    fn_name, _ = _create_lambda(ctx, lambda_role_arn, _HANDLER_SRC)

    marker = ctx.unique_name("sim2real-marker-")
    before = {e["executionArn"] for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"]}

    result = _invoke_lambda(
        ctx, fn_name, {"detail_type": detail_type, "detail": {"marker": marker}}
    )
    assert result["FailedEntryCount"] == 0, f"put_events reported a failed entry: {result}"

    new_exec = _poll_until(
        lambda: [
            e
            for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"]
            if e["executionArn"] not in before
        ],
        lambda execs: len(execs) >= 1,
        timeout_s=60,
        interval_s=2,
    )[0]

    desc = sfn.describe_execution(executionArn=new_exec["executionArn"])
    input_doc = json.loads(desc["input"])
    assert input_doc["detail"]["marker"] == marker, (
        f"expected execution input detail.marker == {marker!r}, got {input_doc.get('detail')!r}"
    )
    assert input_doc["detail-type"] == detail_type, (
        f"expected execution input detail-type == {detail_type!r}, got {input_doc.get('detail-type')!r}"
    )
    assert input_doc["source"] == "sim2real.workflow", (
        f"expected execution input source == 'sim2real.workflow', got {input_doc.get('source')!r}"
    )

    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=new_exec["executionArn"]),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "ABORTED", "TIMED_OUT"),
        timeout_s=30,
        interval_s=1.5,
    )
    assert final["status"] == "SUCCEEDED", (
        f"expected the triggered execution to reach SUCCEEDED, got {final['status']} "
        f"(executionArn={new_exec['executionArn']})"
    )
    _ = sm_name


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_policies: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda n=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    return role_arn


def _create_sfn_role(ctx, inline_policies: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-srole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda n=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    return role_arn


def _create_eventbridge_sfn_role(ctx, sm_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "start-execution"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda(ctx, role_arn: str, handler_src: str, env: dict[str, str] | None = None, timeout: int = 30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    code = _zip_code(handler_src)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    return name, resp["FunctionArn"]


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> tuple[str, str]:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    arn = None
    last_err = None
    for _ in range(12):
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            arn = resp["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = e
            time.sleep(3)
    if arn is None:
        raise last_err
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn, name


def _put_rule_with_sfn_target(ctx, event_pattern: dict[str, Any], sm_arn: str) -> str:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    eb_role_arn = _create_eventbridge_sfn_role(ctx, sm_arn)
    _put_targets_with_retry(ctx, events, rule_name, sm_arn, eb_role_arn)
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sfn-target"]))
    return rule_name


def _put_targets_with_retry(ctx, events, rule_name: str, sm_arn: str, eb_role_arn: str) -> None:
    last_err = None
    for _ in range(12):
        resp = events.put_targets(
            Rule=rule_name, Targets=[{"Id": "sfn-target", "Arn": sm_arn, "RoleArn": eb_role_arn}]
        )
        if resp.get("FailedEntryCount", 0) == 0:
            return
        last_err = resp
        time.sleep(3)
    raise AssertionError(f"put_targets kept failing: {last_err}")


def _invoke_lambda(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload).encode("utf-8"), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised: {body}")
    return body


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
