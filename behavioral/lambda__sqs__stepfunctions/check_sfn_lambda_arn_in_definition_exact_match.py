"""sfn-lambda-arn-in-definition-exact-match."""

from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-lambda-arn-in-definition-exact-match"

GROUP = "overly-permissive"

SERVICES = ["lambda", "stepfunctions", "sqs"]

_MANAGED_TAGS = {"sim2real:managed": "true"}

_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """State machine with wrong Lambda ARN causes execution failure, not silent wrong-target
    invocation — proven against a positive control that the identical Task integration succeeds
    against a real function."""
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-xsvc-role-sfn-wrongarn-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}
            ],
        }
    )
    iam.put_role_policy(
        RoleName=role_name, PolicyName="invoke-any", PolicyDocument=policy_doc
    )
    # An inline policy blocks DeleteRole (DeleteConflictException), so this must run — via the
    # engine's LIFO cleanup order — before the delete_role registered above, or the role and its
    # policy are left behind.
    ctx.on_cleanup(
        lambda: ctx.client("iam").delete_role_policy(
            RoleName=role_name, PolicyName="invoke-any"
        )
    )

    # ---- positive control: an otherwise-identical Task invoking a real function must succeed.
    # Without this, a target that unconditionally fails every lambda:invoke Task — never actually
    # attempting delivery to any function, real or fake — would pass the negative assertion below
    # for free. ----
    fn_arn = _create_echo_lambda(ctx)

    sm_ok_name = ctx.unique_name("sim2real-xsvc-sm-sfn-realarn-")
    definition_ok = json.dumps(
        {
            "StartAt": "InvokeRealLambda",
            "States": {
                "InvokeRealLambda": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                    "ResultSelector": {"body.$": "$.Payload"},
                    "End": True,
                }
            },
        }
    )
    sm_ok = sfn.create_state_machine(
        name=sm_ok_name,
        definition=definition_ok,
        roleArn=role_arn,
        tags=[{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()],
    )
    sm_ok_arn = sm_ok["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(
            stateMachineArn=sm_ok_arn
        )
    )

    desc_ok = _start_until_trust_propagated(sfn, sm_ok_arn, json.dumps({"value": 7}))
    assert desc_ok["status"] == "SUCCEEDED", (
        f"positive control: a Task invoking the real function {fn_arn} must succeed on the "
        f"identical lambda:invoke integration, got {desc_ok['status']} "
        f"(cause={desc_ok.get('cause')!r}) — the FAILED assertion below would be meaningless if "
        f"the integration itself never delivers"
    )
    output = json.loads(desc_ok["output"])
    assert output.get("body", {}).get("value") == 7, (
        f"positive control: expected the echoed body.value=7, got: {output}"
    )

    # ---- break exactly the ARN: an otherwise-identical Task pointed at a function that does not
    # exist must fail the execution, not silently invoke some other target.
    #
    # The ARN's account MUST be the caller's own account. A placeholder account (e.g.
    # 000000000000) makes this a CROSS-account invoke, and Lambda checks the resource-based
    # policy for that BEFORE checking whether the function exists — real AWS returns
    # AccessDeniedException, not ResourceNotFoundException, which is a different contract than
    # the one this check claims to assert. ----
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:lambda:{ctx.region}:{account_id}:function:nonexistent-function-xyz"
    sm_name = ctx.unique_name("sim2real-xsvc-sm-sfn-wrongarn-")
    definition = json.dumps(
        {
            "StartAt": "InvokeFakeLambda",
            "States": {
                "InvokeFakeLambda": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": fake_arn, "Payload.$": "$"},
                    "End": True,
                }
            },
        }
    )
    sm = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=role_arn,
        tags=[{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()],
    )
    sm_arn = sm["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=sm_arn)
    )

    desc = _start_until_trust_propagated(sfn, sm_arn, json.dumps({}))
    assert desc["status"] == "FAILED", (
        f"Expected FAILED for non-existent Lambda ARN, got: {desc['status']}"
    )
    error = desc.get("error", "") or ""
    cause = desc.get("cause", "") or ""
    combined = (error + cause).lower()
    assert any(
        kw in combined
        for kw in ("resourcenotfound", "taskfailed", "notfound", "does not exist")
    ), f"Expected ResourceNotFound/TaskFailed, got error={error}, cause={cause}"


# ===== helpers =====
def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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


def _start_until_trust_propagated(sfn, sm_arn, input_str, max_attempts=8):
    """Start an execution, retrying only while it fails on the IAM role-trust propagation race.

    Returns the terminal describe_execution dict. Raises AssertionError if trust never
    propagates within the budget (a genuine, reportable condition) — never returns a FAILED
    execution that is actually a trust race, which would make the caller's assertions grade the
    wrong thing.
    """
    desc = None
    for attempt in range(max_attempts):
        execution = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)
        exec_arn = execution["executionArn"]
        desc = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
            timeout_s=60,
            interval_s=3,
        )
        if desc["status"] != "FAILED":
            return desc
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in cause for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"Step Functions role trust did not propagate after {max_attempts} attempts "
        f"(last cause: {desc.get('cause') if desc else 'n/a'})"
    )


def _create_echo_lambda(ctx) -> str:
    """A minimal Lambda function that echoes its event; the positive control's invoke target.
    Returns the function ARN."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-xsvc-role-sfn-wrongarn-echo-")
    trust = json.dumps(
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:*:*:*",
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=policy_doc)
    ctx.on_cleanup(
        lambda: ctx.client("iam").delete_role_policy(
            RoleName=role_name, PolicyName="logs"
        )
    )

    fn_name = ctx.unique_name("sim2real-xsvc-fn-sfn-wrongarn-echo-")
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return event\n",
        )

    deadline = time.monotonic() + 30
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_buf.getvalue()},
                Timeout=30,
                MemorySize=128,
                Tags=dict(_MANAGED_TAGS),
            )
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err or RuntimeError(f"Failed to create Lambda {fn_name}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    )

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda r: r.get("State") == "Active",
        timeout_s=60,
        interval_s=2,
        description=f"Lambda {fn_name} active",
    )
    return resp["FunctionArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
