"""cfn-lambda-function-role-cannot-be-assumed-leaves-no-function-good-role-invokes."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-function-role-cannot-be-assumed-leaves-no-function-good-role-invokes"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "lambda", "logs"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
})

_HANDLER_REASON_RE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_HANDLER = "exports.handler = async () => ({ statusCode: 200, body: 'invoked' });"


def _masked(text: str) -> str:
    """``text`` with only its Request ID and SDK Attempt Count (non-deterministic) masked."""
    text = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def _handler_reason(reason: str) -> tuple[str, str]:
    """``(masked message, HandlerErrorCode)`` of a resource-handler failure reason."""
    m = _HANDLER_REASON_RE.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"]), m["code"]


def _template(function_name: str, role_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "nodejs22.x",
                    "Handler": "index.handler",
                    "Role": role_arn,
                    "Code": {"ZipFile": _HANDLER},
                },
            }
        },
    })


def _expect_error(fn, code: str, message: str):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success names its result."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _wait_stack(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status!r})")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        if not status.endswith("IN_PROGRESS"):
            break
        time.sleep(interval_s)
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


def _resource_reason(cfn, stack_name: str, logical_id: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"expected exactly one CREATE_FAILED row for {logical_id}, got {rows!r}"
    assert rows[0] is not None, f"the CREATE_FAILED row for {logical_id} carries no reason"
    return rows[0]


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
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
                raise AssertionError(f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads")
            time.sleep(interval_s)


def _invoke_with_retry(lam, function_name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> dict:
    """Invoke, tolerating the brief window where a freshly created role has not yet propagated."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
        body = json.loads(resp["Payload"].read())
        if resp.get("FunctionError"):
            last_error = body
            time.sleep(interval_s)
            continue
        return body
    raise AssertionError(f"lambda invoke kept failing within {timeout_s}s: {last_error!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An AWS::Lambda::Function whose Role names a nonexistent IAM role rolls the stack back to
    ROLLBACK_COMPLETE with the Function resource's exact CreateFunction refusal, and Lambda never
    holds a function under that name; the same template pointed at an assumable role reaches CREATE_COMPLETE and invokes real code.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    # ---- Negative: the Role ARN names an IAM role that was never created. ----
    bad_stack = ctx.unique_name("sim2real-cfnlambdarole-bad-")
    bad_function_name = ctx.unique_name("sim2real-cfnlambdarole-badfn-")
    bad_role_name = ctx.unique_name("sim2real-cfnlambdarole-ghost-")
    bad_role_arn = f"arn:aws:iam::{ctx.account}:role/{bad_role_name}"

    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_function_name, bad_role_arn),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))

    status = _wait_stack(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"a Role naming a nonexistent IAM role must end exactly ROLLBACK_COMPLETE, got {status!r}"
    )

    reason = _resource_reason(cfn, bad_stack, "Function")
    message, handler_code = _handler_reason(reason)
    assert handler_code == "InvalidRequest", f"expected HandlerErrorCode InvalidRequest, got {handler_code!r} (reason: {reason!r})"
    expected_message = (
        "The role defined for the function cannot be assumed by Lambda. "
        "(Service: Lambda, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r} (reason: {reason!r})"

    _not_found = (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_function_name}",
    )
    _expect_error(lambda: lam.get_function(FunctionName=bad_function_name), *_not_found)

    # ---- Positive control: the identical template, pointed at a role Lambda can assume. ----
    role_name = ctx.unique_name("sim2real-cfnlambdarole-good-")
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

    good_stack = ctx.unique_name("sim2real-cfnlambdarole-good-")
    good_function_name = ctx.unique_name("sim2real-cfnlambdarole-goodfn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{good_function_name}"))

    # The first CreateStack to use the fresh role waits out IAM propagation on its documented
    # refusal, retrying with a brand-new stack each time since a failed CreateStack cannot be
    # retried under the same name until it is rolled back and deleted.
    deadline = time.monotonic() + 120.0
    stack = None
    while True:
        cfn.create_stack(
            StackName=good_stack,
            TemplateBody=_template(good_function_name, role_arn),
            Capabilities=["CAPABILITY_IAM"],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda name=good_stack: _delete_stack(cfn, name))
        stack = _wait_stack(cfn, good_stack, timeout_s=180.0)
        if stack == "CREATE_COMPLETE":
            break
        reason = _resource_reason(cfn, good_stack, "Function")
        _delete_stack(cfn, good_stack)
        if "cannot be assumed by Lambda" not in reason or time.monotonic() >= deadline:
            raise AssertionError(
                f"the positive control (a role Lambda can assume) must reach CREATE_COMPLETE "
                f"once IAM propagation settles, got {stack!r} with reason {reason!r}"
            )
        time.sleep(5)

    conf = lam.get_function(FunctionName=good_function_name)["Configuration"]
    assert conf["Role"] == role_arn, f"expected the function's Role to be {role_arn!r}, got {conf['Role']!r}"

    payload = _invoke_with_retry(lam, good_function_name)
    assert payload == {"statusCode": 200, "body": "invoked"}, (
        f"the positive control must actually invoke, got {payload!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
