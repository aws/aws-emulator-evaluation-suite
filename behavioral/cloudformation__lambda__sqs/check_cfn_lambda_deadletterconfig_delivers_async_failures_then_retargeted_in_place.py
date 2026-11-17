"""cfn-lambda-deadletterconfig-delivers-async-failures-then-retargeted-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-deadletterconfig-delivers-async-failures-then-retargeted-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs", "sqs"]

_STACK_CAP_S = 300.0
_POLL_S = 2.0
_RECEIVE_CAP_S = 90.0
_RETARGET_CAP_S = 360.0

_HANDLER = (
    "def handler(event, context):\n"
    "    raise RuntimeError('sim2real-async-failure')\n"
)


def _role_trust() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })


def _role_policy(ctx, queue_arns: list[str]) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"arn:aws:logs:{ctx.region}:{ctx.account}:*",
            },
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": queue_arns,
            },
        ],
    })


def _template(function_name: str, role_arn: str, dlq_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": role_arn,
                    "Code": {"ZipFile": _HANDLER},
                    "Timeout": 15,
                    "MemorySize": 128,
                    "DeadLetterConfig": {"TargetArn": dlq_arn},
                },
            },
            "Invoker": {
                "Type": "AWS::Lambda::EventInvokeConfig",
                "Properties": {
                    "FunctionName": {"Ref": "Fn"},
                    "Qualifier": "$LATEST",
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                },
            },
        },
        "Outputs": {
            "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
        },
    })


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation-deployed function's DeadLetterConfig.TargetArn delivers a failed
    asynchronous invocation to the named queue, reads back through Lambda, and an in-place
    update retargets delivery to a second queue without replacing the function.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-deadletterconfig.html
    """
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    q1_name = ctx.unique_name("sim2real-cfndlq-q1-")
    q2_name = ctx.unique_name("sim2real-cfndlq-q2-")
    q1_url = sqs.create_queue(QueueName=q1_name)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, q1_url))
    q2_url = sqs.create_queue(QueueName=q2_name)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, q2_url))
    q1_arn = _queue_arn(sqs, q1_url)
    q2_arn = _queue_arn(sqs, q2_url)

    role_name = ctx.unique_name("sim2real-cfndlq-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_role_trust(), Path="/sim2real/",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-dlq-send",
        PolicyDocument=_role_policy(ctx, [q1_arn, q2_arn]),
    )
    _wait_simulated_allowed(iam, role_arn, "sqs:SendMessage", [q1_arn, q2_arn])

    name = ctx.unique_name("sim2real-cfndlq-fn-")
    stack_name = ctx.unique_name("sim2real-cfndlq-stack-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: DeadLetterConfig targets the first queue
    stack = _create_stack_retrying_role_propagation(
        ctx, cfn, stack_name, _template(name, role_arn, q1_arn), ref,
    )
    assert _physical_ids(cfn, ref["stack"])["Fn"] == name, (
        f"the function's physical id must be its FunctionName {name!r}"
    )
    _assert_dlq(lam, name, q1_arn)

    lam.invoke(FunctionName=name, InvocationType="Event", Payload=b"{}")
    first = _receive_one(ctx, sqs, q1_url)
    attrs = first["MessageAttributes"]
    assert attrs["ErrorCode"]["StringValue"] == "200", (
        f"DLQ ErrorCode attribute was {attrs['ErrorCode']!r}, expected the synchronous-equivalent '200'"
    )
    assert "sim2real-async-failure" in attrs["ErrorMessage"]["StringValue"], (
        f"DLQ ErrorMessage attribute {attrs['ErrorMessage']!r} must carry the handler's own message"
    )
    assert attrs["RequestID"]["StringValue"], "DLQ RequestID attribute must be present and non-empty"
    assert json.loads(first["Body"]) == {}, f"DLQ message body {first['Body']!r} must be the sent event"
    sqs.delete_message(QueueUrl=q1_url, ReceiptHandle=first["ReceiptHandle"])

    # ---- 2. in-place update: DeadLetterConfig is not create-only
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(name, role_arn, q2_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Fn"] == name, (
        "a DeadLetterConfig.TargetArn update must keep the same function, not replace it"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Fn"), name)
    _assert_dlq(lam, name, q2_arn)

    # Lambda's async event pipeline refreshes a function's config on its own schedule, lagging
    # CloudFormation's own report that the update is complete; retry the invocation itself,
    # draining any failure that still lands on the stale target, until the new one receives.
    second = _invoke_until_delivered(ctx, lam, sqs, name, q2_url, q1_url)
    sqs.delete_message(QueueUrl=q2_url, ReceiptHandle=second["ReceiptHandle"])
    stale = _receive_none(sqs, q1_url)
    assert stale == [], f"the retargeted function must not still deliver to the old queue: {stale!r}"

    # ---- 3. delete: Lambda no longer knows the function
    _delete_stack(ctx, cfn, ref["stack"])
    fn_arn = _outputs(stack)["FnArn"]
    got = _wait_error(ctx, lambda: lam.get_function(FunctionName=name), "ResourceNotFoundException")
    want = ("ResourceNotFoundException", f"Function not found: {fn_arn}")
    assert got == want, f"GetFunction after the stack delete answered {got!r}, expected {want!r}"


def _assert_dlq(lam, name: str, target_arn: str) -> None:
    config = lam.get_function_configuration(FunctionName=name)
    got = config.get("DeadLetterConfig", {}).get("TargetArn")
    assert got == target_arn, f"GetFunctionConfiguration {name} DeadLetterConfig.TargetArn={got!r}, expected {target_arn!r}"


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _delete_queue(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise


def _delete_role(iam, role_name: str) -> None:
    try:
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_simulated_allowed(iam, role_arn: str, action: str, resource_arns: list[str],
                            *, budget_s: float = 90.0, interval_s: float = 3.0) -> None:
    """Bounded retry on the role's own first use: wait until the inline policy this check just
    attached actually evaluates to allowed, rather than racing IAM's propagation lag."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        results = iam.simulate_principal_policy(
            PolicySourceArn=role_arn, ActionNames=[action], ResourceArns=resource_arns,
        )["EvaluationResults"]
        last = {r["EvalResourceName"]: r["EvalDecision"] for r in results}
        if all(v == "allowed" for v in last.values()):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{action} on {resource_arns} never simulated as allowed: {last!r}")
        time.sleep(interval_s)


def _create_stack_retrying_role_propagation(ctx, cfn, stack_name: str, template: str, ref: dict,
                                            *, budget_s: float = 180.0) -> dict:
    """Create *stack_name*, retrying the whole stack on the role's first real use by Lambda.

    IAM's trust-policy propagation lands after CloudFormation's single internal attempt, so a
    stack that failed only on "cannot be assumed by Lambda" is deleted and recreated rather than
    treated as a defect in the function itself (the bounded retry B7 asks for, at this check's
    first use of the role it just created).
    """
    deadline = time.monotonic() + budget_s
    while True:
        ref["stack"] = cfn.create_stack(
            StackName=stack_name, TemplateBody=template,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["StackId"]
        stack = _settle(ctx, cfn, ref["stack"])
        if stack["StackStatus"] == "CREATE_COMPLETE":
            return stack
        reasons = [
            e.get("ResourceStatusReason", "")
            for e in _events(cfn, ref["stack"])
            if e["ResourceStatus"] == "CREATE_FAILED"
        ]
        if not any("cannot be assumed by Lambda" in r for r in reasons) or time.monotonic() >= deadline:
            _expect(cfn, stack, "CREATE_COMPLETE")
        _delete_stack(ctx, cfn, ref["stack"])
        time.sleep(_POLL_S)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent.

    A buffered log stream can recreate the group after the delete that was meant to remove it,
    so one delete is not a teardown; raises if it keeps coming back past its own budget.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = any(
            g["logGroupName"] == name
            for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        )
        if present:
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
                raise AssertionError(f"{name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


# ===== CloudFormation polling and inspection helpers =====


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _settle(ctx, cfn, stack_id: str) -> dict:
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s")
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str) -> None:
    statuses = [status for status, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"the function must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][1] == physical_id, (
        f"the update must complete on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _invoke_until_delivered(ctx, lam, sqs, name: str, want_url: str, stale_url: str,
                            *, budget_s: float = _RETARGET_CAP_S, attempt_wait_s: float = 10.0) -> dict:
    """Invoke *name* asynchronously until a failure is delivered to *want_url*.

    Each attempt waits only *attempt_wait_s* on the new target; a failure that lands on
    *stale_url* in the meantime is drained so it cannot be mistaken for the next attempt's
    delivery, and invocation repeats until the budget runs out.
    """
    deadline = time.monotonic() + min(budget_s, _budget_s(ctx, budget_s))
    while True:
        lam.invoke(FunctionName=name, InvocationType="Event", Payload=b"{}")
        attempt_deadline = time.monotonic() + attempt_wait_s
        while time.monotonic() < attempt_deadline:
            msgs = sqs.receive_message(
                QueueUrl=want_url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
            ).get("Messages", [])
            if msgs:
                return msgs[0]
        for stray in sqs.receive_message(
            QueueUrl=stale_url, MaxNumberOfMessages=10, WaitTimeSeconds=0,
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=stale_url, ReceiptHandle=stray["ReceiptHandle"])
        if time.monotonic() >= deadline:
            raise AssertionError(f"no failure delivered to {want_url} within {budget_s:.0f}s")


def _receive_one(ctx, sqs, url: str, *, budget_s: float = _RECEIVE_CAP_S) -> dict:
    deadline = time.monotonic() + min(budget_s, _budget_s(ctx, budget_s))
    while True:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        ).get("Messages", [])
        if msgs:
            return msgs[0]
        if time.monotonic() >= deadline:
            raise AssertionError(f"no message arrived on {url} within {budget_s:.0f}s")


def _receive_none(sqs, url: str) -> list:
    return sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
    ).get("Messages", [])


def _wait_error(ctx, fn, code: str):
    timeout = _budget_s(ctx, 120.0)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"still answering after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _stack_status_or_gone(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    status = _stack_status_or_gone(cfn, ref["stack"])
    if status == "GONE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(ctx, cfn, ref["stack"])
    _delete_stack(ctx, cfn, ref["stack"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
