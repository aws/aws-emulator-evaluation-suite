"""cfn-sqs-event-source-mapping-create-rejects-a-role-without-receive-permission."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-event-source-mapping-create-rejects-a-role-without-receive-permission"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "sqs", "ssm"]

_TERMINAL_BUDGET_S = 420.0
_DELIVERY_BUDGET_S = 120.0
_DRAIN_BUDGET_S = 60.0
_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_REASON = re.compile(
    re.escape('Resource handler returned message: "Invalid request provided: The function '
              'execution role does not have permissions to call ReceiveMessage on SQS '
              "(Service: Lambda, Status Code: 400, Request ID: ")
    + _ID + re.escape(") (SDK Attempt Count: ") + r"[0-9]+" + re.escape(')" (RequestToken: ')
    + _ID + re.escape(", HandlerErrorCode: InvalidRequest)"))

_HANDLER_CODE = """
import json
import os

import boto3

PARAM_NAME = os.environ["PARAM_NAME"]
ssm = boto3.client("ssm")


def handler(event, context):
    for record in event["Records"]:
        body = json.loads(record["body"])
        ssm.put_parameter(Name=PARAM_NAME, Value=body["marker"], Type="String", Overwrite=True)
    return {"processed": len(event["Records"])}
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Lambda::EventSourceMapping whose function role lacks `sqs:ReceiveMessage` fails with
    Lambda's exact refusal and the stack rolls back to nothing; the same stack with the permission
    granted consumes a message and drains the queue.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    logs = ctx.client("logs")

    bad_stack = ctx.unique_name("sim2real-cfnesmbad-")
    bad_function_name = ctx.unique_name("sim2real-cfnesmbad-fn-")
    bad_role_name = ctx.unique_name("sim2real-cfnesmbad-role-")
    bad_queue_name = ctx.unique_name("sim2real-cfnesmbad-q-")
    param_name = "/" + ctx.unique_name("sim2real-cfnesm-param-")
    param_arn = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{param_name}"

    ctx.on_cleanup(lambda: _delete_parameter(ssm, param_name))

    bad_template = _template(
        function_name=bad_function_name, role_name=bad_role_name, queue_name=bad_queue_name,
        param_name=param_name, param_arn=param_arn, grant_queue_access=False,
    )

    cfn.create_stack(
        StackName=bad_stack, TemplateBody=json.dumps(bad_template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack))
    # The rollback deletes the function itself, but not its log group (it is not a stack
    # resource) -- register the reap now, before the rollback, so LIFO runs it after.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{bad_function_name}"))

    bad_status = _wait_terminal(cfn, bad_stack, budget_s=_TERMINAL_BUDGET_S)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} whose role has no sqs:ReceiveMessage on the queue reached "
        f"{bad_status!r}, expected ROLLBACK_COMPLETE -- an emulator that lets this CREATE_COMPLETE "
        f"stood up a mapping that could never deliver"
    )
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_stack)
              for e in page["StackEvents"]]
    mapping_failures = [
        e.get("ResourceStatusReason") or "" for e in events
        if e["LogicalResourceId"] == "Mapping" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(mapping_failures) == 1, (
        f"expected one CREATE_FAILED event for the Mapping resource in {bad_stack!r}, got "
        f"{mapping_failures!r}"
    )
    assert _REASON.fullmatch(mapping_failures[0]), (
        f"Mapping's CREATE_FAILED reason is {mapping_failures[0]!r}, expected Lambda's exact "
        f"refusal of a role without ReceiveMessage on the queue"
    )
    resources = cfn.describe_stack_resources(StackName=bad_stack)["StackResources"]
    live = [r for r in resources if r["ResourceStatus"] != "DELETE_COMPLETE"]
    assert live == [], (
        f"stack {bad_stack!r} rolled back, so every resource it created must itself be "
        f"DELETE_COMPLETE; still live: "
        f"{[(r['LogicalResourceId'], r['ResourceStatus']) for r in live]!r}"
    )
    _assert_gone(ctx, function_name=bad_function_name, queue_name=bad_queue_name,
                 role_name=bad_role_name, what="the rollback")
    _delete_stack_and_wait(cfn, bad_stack)
    bad_gone = _error(lambda: cfn.describe_stacks(StackName=bad_stack))
    assert bad_gone == ("ValidationError", f"Stack with id {bad_stack} does not exist"), (
        f"DescribeStacks on the deleted rolled-back stack {bad_stack!r} returned {bad_gone!r}"
    )

    # Positive control: the identical shape, with the one permission granted, actually works.
    good_stack = ctx.unique_name("sim2real-cfnesmgood-")
    good_function_name = ctx.unique_name("sim2real-cfnesmgood-fn-")
    good_role_name = ctx.unique_name("sim2real-cfnesmgood-role-")
    good_queue_name = ctx.unique_name("sim2real-cfnesmgood-q-")

    good_template = _template(
        function_name=good_function_name, role_name=good_role_name, queue_name=good_queue_name,
        param_name=param_name, param_arn=param_arn, grant_queue_access=True,
    )
    cfn.create_stack(
        StackName=good_stack, TemplateBody=json.dumps(good_template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack))
    good_status = _wait_terminal(cfn, good_stack, budget_s=_TERMINAL_BUDGET_S)
    assert good_status == "CREATE_COMPLETE", (
        f"stack {good_stack!r} with sqs:ReceiveMessage granted reached {good_status!r}, "
        f"expected CREATE_COMPLETE"
    )

    queue_url = sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"]
    mappings = lam.list_event_source_mappings(FunctionName=good_function_name)["EventSourceMappings"]
    assert len(mappings) == 1, f"expected one mapping on {good_function_name!r}, got {mappings!r}"
    mapping_uuid = mappings[0]["UUID"]
    marker = ctx.unique_name("marker-")
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps({"marker": marker}))
    delivered = _poll_parameter_equals(ssm, param_name, marker, budget_s=_DELIVERY_BUDGET_S)
    assert delivered, (
        f"SSM parameter {param_name!r} never became {marker!r} within {_DELIVERY_BUDGET_S}s "
        f"with sqs:ReceiveMessage granted -- the only difference from the rejected stack is "
        f"that one permission"
    )
    _poll_queue_drained(sqs, queue_url, budget_s=_DRAIN_BUDGET_S)

    _delete_stack_and_wait(cfn, good_stack)
    _reap_log_group(logs, f"/aws/lambda/{good_function_name}")

    good_gone = _error(lambda: cfn.describe_stacks(StackName=good_stack))
    assert good_gone == ("ValidationError", f"Stack with id {good_stack} does not exist"), (
        f"DescribeStacks on the deleted stack {good_stack!r} returned {good_gone!r}"
    )
    _assert_gone(ctx, function_name=good_function_name, queue_name=good_queue_name,
                 role_name=good_role_name, what="the stack delete")
    mapping_gone = _error(lambda: lam.get_event_source_mapping(UUID=mapping_uuid))
    assert mapping_gone == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"GetEventSourceMapping after the stack delete returned {mapping_gone!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _assert_gone(ctx, *, function_name: str, queue_name: str, role_name: str, what: str) -> None:
    """The function, queue and role each answer their own service's exact not-found."""
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    lam, sqs, iam = ctx.client("lambda"), ctx.client("sqs"), ctx.client("iam")
    got = _error(lambda: lam.get_function(FunctionName=function_name))
    assert got == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction({function_name!r}) after {what} returned {got!r}"
    )
    got = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert got == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"GetQueueUrl({queue_name!r}) after {what} returned {got!r}"
    )
    got = _error(lambda: iam.get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole({role_name!r}) after {what} returned {got!r}"
    )


def _template(*, function_name: str, role_name: str, queue_name: str, param_name: str,
              param_arn: str, grant_queue_access: bool) -> dict:
    """The Function+Queue+EventSourceMapping shape; `grant_queue_access` is the one thing
    that varies between the rejected stack and its positive control."""
    statements = [{"Effect": "Allow", "Action": "ssm:PutParameter", "Resource": param_arn}]
    if grant_queue_access:
        statements.append({
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
        })
    return {
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [{
                        "PolicyName": "worker-policy",
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
                    }],
                },
            },
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name, "VisibilityTimeout": 30},
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 20,
                    "Environment": {"Variables": {"PARAM_NAME": param_name}},
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
            "Mapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "FunctionName": {"Ref": "Fn"},
                    "EventSourceArn": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "BatchSize": 1,
                    "Enabled": True,
                },
            },
        },
    }


def _wait_terminal(cfn, stack: str, *, budget_s: float, poll_s: float = 2.0) -> str:
    """Poll `StackStatus` to a `*_COMPLETE`/`*_FAILED` terminal state."""
    deadline = time.monotonic() + budget_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if last.endswith("_COMPLETE") or last.endswith("_FAILED"):
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"stack {stack!r} never reached a terminal status within {budget_s}s (last {last!r})"
    )


def _poll_parameter_equals(ssm, name: str, want: str, *, budget_s: float,
                           poll_s: float = 2.0) -> bool:
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        try:
            value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        else:
            if value == want:
                return True
        time.sleep(poll_s)
    return False


def _poll_queue_drained(sqs, queue_url: str, *, budget_s: float, poll_s: float = 2.0) -> None:
    deadline = time.monotonic() + budget_s
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        last = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        if (last.get("ApproximateNumberOfMessages") == "0"
                and last.get("ApproximateNumberOfMessagesNotVisible") == "0"):
            return
        time.sleep(poll_s)
    raise AssertionError(f"queue {queue_url!r} never drained within {budget_s}s (last {last!r})")


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _delete_stack_and_wait(cfn, stack: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (exc.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in exc.response["Error"].get("Message", "")):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(2.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 90.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
