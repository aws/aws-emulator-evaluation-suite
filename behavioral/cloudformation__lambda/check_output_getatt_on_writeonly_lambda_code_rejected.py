"""output-getatt-on-writeonly-lambda-code-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "output-getatt-on-writeonly-lambda-code-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}

_CODE = "def handler(event, context):\n    return 'ok'\n"
_STACK = "<stack>"


def _template(function_name: str, role_arn: str, output) -> str:
    body = {
        "Resources": {
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 10,
                    "Role": role_arn,
                    "Code": {"ZipFile": _CODE},
                },
            }
        }
    }
    if output is not None:
        body["Outputs"] = {"Out": {"Value": output}}
    return json.dumps(body)


def _wait_terminal(cf, stack_id, *, timeout_s=300.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        s = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if s["StackStatus"] in _TERMINAL:
            return s
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} stuck at {s['StackStatus']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_stack_and_wait(cf, stack_id: str) -> None:
    """Delete by stack id and wait; anything but DELETE_COMPLETE raises."""
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id)["StackStatus"]
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _rows(cf, stack_id: str) -> list[tuple]:
    """``(logical id, status, reason)`` of every stack event, oldest first; the stack is ``<stack>``."""
    events = [e for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    return [(_STACK if e["LogicalResourceId"] == e["StackName"] else e["LogicalResourceId"],
             e["ResourceStatus"], e.get("ResourceStatusReason")) for e in reversed(events)]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """True when every ``(logical id, status)`` of ``wanted`` occurs in ``rows`` in that order."""
    it = iter(r[:2] for r in rows)
    return all(w in it for w in wanted)


def _create_stack_retrying_role_propagation(ctx, template, *, attempts=5, delay_s=10.0):
    """Create a fresh stack from ``template``, retrying the whole create while the only failure
    is the fresh role not yet being assumable by Lambda; IAM exposes no condition to poll."""
    cf = ctx.client("cloudformation")
    last = None
    for _ in range(attempts):
        stack_id = cf.create_stack(
            StackName=ctx.unique_name("sim2real-behav-lamga-"), TemplateBody=template,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["StackId"]
        ctx.on_cleanup(lambda sid=stack_id: _delete_stack_and_wait(cf, sid))
        last = _wait_terminal(cf, stack_id)
        if last["StackStatus"] != "ROLLBACK_COMPLETE":
            return stack_id, last
        role_not_ready = any(
            "cannot be assumed by Lambda" in (r[2] or "") for r in _rows(cf, stack_id)
        )
        if not role_not_ready:
            return stack_id, last
        _delete_stack_and_wait(cf, stack_id)
        time.sleep(delay_s)
    raise AssertionError(
        f"the execution role never became assumable across {attempts} attempts; last status "
        f"{last['StackStatus']!r}: {last.get('StackStatusReason')!r}"
    )


def _invoke_with_retry(lam, function_name: str, *, timeout_s=90.0, interval_s=3.0):
    """Invoke, tolerating the brief window where a fresh execution role is not yet assumable."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
        body = resp["Payload"].read()
        if resp.get("FunctionError"):
            last = body
            time.sleep(interval_s)
            continue
        return json.loads(body)
    raise AssertionError(f"lambda invoke kept failing within {timeout_s}s: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered invocation can flush and recreate the group after the function's own delete, so
    one delete is one round, not a teardown.
    """
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
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
    "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A template whose Output does Fn::GetAtt on the write-only Code rolls the stack back with
    the exact readonly-attribute reason after building and deleting the function, which is then
    absent from Lambda; the same template with the bad Output removed deploys and runs.
    """
    cf = ctx.client("cloudformation")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    role_name = ctx.unique_name("sim2real-behav-lamga-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    ), "NoSuchEntity"))

    bad_function_name = ctx.unique_name("sim2real-behav-lamga-bad-fn-")
    bad_template = _template(bad_function_name, role_arn, {"Fn::GetAtt": ["Fn", "Code.ZipFile"]})
    bad_stack, bad = _create_stack_retrying_role_propagation(ctx, bad_template)
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE, got {bad['StackStatus']!r}: {bad.get('StackStatusReason')!r}"
    )

    # The output failure is reported only on the stack's own rollback event, so that row's
    # reason is graded, together with the terminal rows that bracket it.
    expected_reason = (
        "Requested attribute Code.ZipFile must be a readonly property in schema for "
        "AWS::Lambda::Function. Rollback requested by user."
    )
    rows = _rows(cf, bad_stack)
    reasons = [r[2] for r in rows if r[:2] == (_STACK, "ROLLBACK_IN_PROGRESS")]
    assert reasons == [expected_reason], (
        f"expected one stack rollback reason {expected_reason!r}, got {reasons!r}"
    )
    wanted = [("Fn", "CREATE_COMPLETE"), (_STACK, "ROLLBACK_IN_PROGRESS"),
              ("Fn", "DELETE_COMPLETE"), (_STACK, "ROLLBACK_COMPLETE")]
    assert _in_order(rows, wanted), (
        f"the function must be built, then deleted by the rollback; expected {wanted!r} in order, "
        f"got {[r[:2] for r in rows]!r}"
    )

    # The rolled-back function is absent from Lambda, before the stack's own delete.
    code, message = _error(lambda: lam.get_function(FunctionName=bad_function_name))
    expected_fn_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:<account>:function:{bad_function_name}"
    )
    assert (code, (message or "").replace(ctx.account, "<account>")) == (
        "ResourceNotFoundException", expected_fn_message
    ), (
        f"a rolled-back stack must leave no function behind; GetFunction({bad_function_name!r}) "
        f"gave {code!r}: {message!r}"
    )

    # Positive control: the identical resource, without the write-only GetAtt, deploys cleanly.
    good_function_name = ctx.unique_name("sim2real-behav-lamga-good-fn-")
    # Registered before the stack's own delete, so LIFO reaps the log group AFTER the function
    # is gone: a buffered invocation can flush and recreate the group right after the delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{good_function_name}"))
    good_template = _template(good_function_name, role_arn, {"Ref": "Fn"})
    good_stack, good = _create_stack_retrying_role_propagation(ctx, good_template)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"the positive control must reach CREATE_COMPLETE, got {good['StackStatus']!r}: "
        f"{good.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good.get("Outputs", [])}
    assert outputs.get("Out") == good_function_name, (
        f"Ref of the function must be its name {good_function_name!r}; got {outputs!r}"
    )
    config = lam.get_function(FunctionName=good_function_name)["Configuration"]
    seen = {k: config.get(k) for k in ("FunctionName", "Runtime", "Handler", "Timeout", "Role")}
    want = {"FunctionName": good_function_name, "Runtime": "python3.12",
            "Handler": "index.handler", "Timeout": 10, "Role": role_arn}
    assert seen == want, f"the control function reads back as {seen!r}, expected {want!r}"
    result = _invoke_with_retry(lam, good_function_name)
    assert result == "ok", f"the positive control's function must actually run, got {result!r}"


def _error(fn):
    """The captured AWS (code, message); an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
