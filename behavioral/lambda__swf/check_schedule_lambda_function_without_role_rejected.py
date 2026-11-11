"""schedule-lambda-function-without-role-rejected."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-lambda-function-without-role-rejected"
GROUP = "lambda-task"
SERVICES = ["lambda", "swf"]

_WF_VERSION = "1.0"

_TERMINAL_LAMBDA_EVENTS = frozenset({
    "LambdaFunctionCompleted", "LambdaFunctionFailed", "LambdaFunctionTimedOut",
    "StartLambdaFunctionFailed", "ScheduleLambdaFunctionFailed",
})

_HANDLER = """
def handler(event, context):
    numbers = event.get("numbers", [])
    return {"sum": sum(numbers)}
"""


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:data-plane",
    "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """Without a lambdaRole, a ScheduleLambdaFunction decision is recorded but the function never
    starts (StartLambdaFunctionFailed, ASSUME_ROLE_FAILED); the same function with a role completes.
    The failure surfaces only in the history, not on the RespondDecisionTaskCompleted response."""
    swf = ctx.client("swf")

    exec_role_name, exec_role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    fn_name, fn_arn = _create_function_with_retry(ctx, exec_role_arn)

    domain = _shared_domain(ctx)
    # Two DIFFERENT task lists: the negative workflow's follow-up decision task (SWF
    # schedules one right after StartLambdaFunctionFailed) is never answered, and a shared
    # task list would let poll_for_decision_task hand it to the positive control's poll
    # instead of the control's own fresh decision task.
    task_list_norole = ctx.unique_name("sim2real-behav-swflam-norole-tl-")
    task_list_ctrl = ctx.unique_name("sim2real-behav-swflam-ctrl-tl-")
    wf_type = {"name": ctx.unique_name("sim2real-swflam-norole-wf-type-"), "version": _WF_VERSION}
    swf.register_workflow_type(
        domain=domain, name=wf_type["name"], version=_WF_VERSION,
        defaultTaskList={"name": task_list_norole},
        defaultTaskStartToCloseTimeout="60",
        defaultExecutionStartToCloseTimeout="600",
        defaultChildPolicy="TERMINATE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", wf_type))

    # ---- the negative: no lambdaRole on this workflow execution ----
    workflow_id = ctx.unique_name("sim2real-swflam-norole-wf-")
    run_id = swf.start_workflow_execution(
        domain=domain, workflowId=workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list_norole},
    )["runId"]
    execution = {"workflowId": workflow_id, "runId": run_id}
    ctx.on_cleanup(lambda: _ignore_unknown(
        lambda: swf.terminate_workflow_execution(domain=domain, workflowId=workflow_id, runId=run_id)
    ))

    started = swf.get_workflow_execution_history(domain=domain, execution=execution)["events"][0]
    assert "lambdaRole" not in started["workflowExecutionStartedEventAttributes"], (
        f"expected no lambdaRole on the started event, got "
        f"{started['workflowExecutionStartedEventAttributes'].get('lambdaRole')!r}"
    )

    task = _poll_decision_task(ctx, domain, task_list_norole)
    swf.respond_decision_task_completed(
        taskToken=task["taskToken"],
        decisions=[{
            "decisionType": "ScheduleLambdaFunction",
            "scheduleLambdaFunctionDecisionAttributes": {
                "id": "sim2real-lam-norole-1",
                "name": fn_name,
                "control": "sim2real-ctl",
                "input": json.dumps({"numbers": [1, 2, 3]}),
                "startToCloseTimeout": "30",
            },
        }],
    )
    events = _poll_until(
        lambda: swf.get_workflow_execution_history(domain=domain, execution=execution)["events"],
        lambda evs: any(e["eventType"] in _TERMINAL_LAMBDA_EVENTS for e in evs),
        timeout_s=30, interval_s=2, description="lambda schedule without role to settle",
    )
    scheduled = next(e for e in events if e["eventType"] == "LambdaFunctionScheduled")
    assert scheduled["lambdaFunctionScheduledEventAttributes"]["name"] == fn_name, scheduled

    failed = next(e for e in events if e["eventType"] == "StartLambdaFunctionFailed")
    cause = failed["startLambdaFunctionFailedEventAttributes"].get("cause")
    assert cause == "ASSUME_ROLE_FAILED", f"expected cause ASSUME_ROLE_FAILED, got {cause!r}"

    # effect absent: the function never actually started or ran, not merely that we never
    # observed a completion -- SWF only emits Started once Lambda actually begins executing.
    started_types = [e["eventType"] for e in events if e["eventType"].startswith("LambdaFunctionStart")]
    assert started_types == [], f"expected no LambdaFunctionStarted event, got {started_types!r}"
    completed_types = [e["eventType"] for e in events if e["eventType"] == "LambdaFunctionCompleted"]
    assert completed_types == [], f"expected no LambdaFunctionCompleted event, got {completed_types!r}"

    # ---- positive control: same domain, same function, this time WITH a role ----
    invoke_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
    }
    invoke_role_name, invoke_role_arn = _create_role(
        ctx, "swf.amazonaws.com", inline_policy=invoke_policy,
    )
    # No fixed wait for the new role: the control loop below retries exactly the two propagation
    # outcomes (ASSUME_ROLE_FAILED, an invoke denial) until its deadline.

    control_workflow_id = ctx.unique_name("sim2real-swflam-ctrl-wf-")
    control_run_id = swf.start_workflow_execution(
        domain=domain, workflowId=control_workflow_id,
        workflowType=wf_type,
        taskList={"name": task_list_ctrl},
        lambdaRole=invoke_role_arn,
    )["runId"]
    control_execution = {"workflowId": control_workflow_id, "runId": control_run_id}

    control_task = _poll_decision_task(ctx, domain, task_list_ctrl)
    deadline = time.monotonic() + 90
    attempt = 0
    completed_event = None
    while True:
        attempt += 1
        before_ids = {
            e["eventId"] for e in swf.get_workflow_execution_history(
                domain=domain, execution=control_execution
            )["events"]
        }
        swf.respond_decision_task_completed(
            taskToken=control_task["taskToken"],
            decisions=[{
                "decisionType": "ScheduleLambdaFunction",
                "scheduleLambdaFunctionDecisionAttributes": {
                    "id": f"sim2real-lam-ctrl-{attempt}",
                    "name": fn_name,
                    "control": "sim2real-ctl",
                    "input": json.dumps({"numbers": [1, 2, 3]}),
                    "startToCloseTimeout": "30",
                },
            }],
        )
        control_events = _poll_until(
            lambda: swf.get_workflow_execution_history(
                domain=domain, execution=control_execution
            )["events"],
            lambda evs: any(
                e["eventId"] not in before_ids and e["eventType"] in _TERMINAL_LAMBDA_EVENTS
                for e in evs
            ),
            timeout_s=30, interval_s=2, description=f"control attempt {attempt} to settle",
        )
        new_terminal = next(
            e for e in control_events
            if e["eventId"] not in before_ids and e["eventType"] in _TERMINAL_LAMBDA_EVENTS
        )
        if new_terminal["eventType"] == "LambdaFunctionCompleted":
            completed_event = new_terminal
            break
        start_failed_attrs = new_terminal.get("startLambdaFunctionFailedEventAttributes", {})
        failed_attrs = new_terminal.get("lambdaFunctionFailedEventAttributes", {})
        is_assume_role_propagation = (
            new_terminal["eventType"] == "StartLambdaFunctionFailed"
            and start_failed_attrs.get("cause") == "ASSUME_ROLE_FAILED"
        )
        is_invoke_policy_propagation = (
            new_terminal["eventType"] == "LambdaFunctionFailed"
            and any(
                code in failed_attrs.get("details", "")
                for code in ("AccessDeniedException", "UnrecognizedClientException")
            )
        )
        if (is_assume_role_propagation or is_invoke_policy_propagation) and time.monotonic() < deadline:
            control_task = _poll_decision_task(ctx, domain, task_list_ctrl)
            continue
        raise AssertionError(
            f"positive control did not complete; got {new_terminal['eventType']!r} "
            f"attrs={new_terminal!r}"
        )

    control_attrs = completed_event["lambdaFunctionCompletedEventAttributes"]
    assert json.loads(control_attrs["result"]) == {"sum": 6}, (
        f"positive control: expected Lambda result {{'sum': 6}}, got {control_attrs['result']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ignore_unknown(fn):
    try:
        fn()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") not in ("UnknownResourceFault",):
            raise


def _poll_decision_task(ctx, domain, task_list, attempts=15):
    swf = ctx.client("swf")
    for _ in range(attempts):
        task = swf.poll_for_decision_task(
            domain=domain, taskList={"name": task_list}, identity="sim2real-decider",
        )
        if task.get("taskToken"):
            return task
    raise AssertionError("no decision task became available")


def _create_role(ctx, trust_service, inline_policy=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-swflam-norole-role-{trust_service.split('.')[0]}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
                           Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return role_name, resp["Role"]["Arn"]


def _delete_role(ctx, role_name):
    """Inline policies, attachments, then the role; a failure other than already-gone RAISES."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _reap_log_group(ctx, log_group_name, window_s=45.0):
    """One net registered before the function exists, so LIFO runs it AFTER delete_function:
    a stream buffered by an invocation that already returned can flush after the delete and
    recreate the group, so re-delete over a bounded window rather than once."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + window_s
    while True:
        try:
            logs.delete_log_group(logGroupName=log_group_name)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        if time.monotonic() >= deadline:
            return
        time.sleep(5)


def _create_function_with_retry(ctx, role_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-swflam-norole-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", _HANDLER)
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=10,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=60.0, interval_s=2.0, description=f"Lambda {name} Active",
    )
    return name, resp["FunctionArn"]


_SHARED_DOMAIN = "sim2real-swf-shared"


def _shared_domain(ctx) -> str:
    """The account's shared SWF domain, registered if absent and never deprecated: SWF has no
    DeleteDomain, and a deprecated domain counts toward the registered-domain quota."""
    swf = ctx.client("swf")
    try:
        status = swf.describe_domain(name=_SHARED_DOMAIN)["domainInfo"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise
        status = None
    try:
        if status is None:
            swf.register_domain(
                name=_SHARED_DOMAIN,
                workflowExecutionRetentionPeriodInDays="1",
                tags=[{"key": "sim2real:infra", "value": "swf-shared"}],
            )
        elif status == "DEPRECATED":
            swf.undeprecate_domain(name=_SHARED_DOMAIN)
    except ClientError as exc:
        # A concurrent run registered or restored it first.
        if exc.response["Error"]["Code"] != "DomainAlreadyExistsFault":
            raise
    return _SHARED_DOMAIN


def _delete_type(swf, domain: str, kind: str, type_ref: dict) -> None:
    """Teardown: deprecate then delete a workflow or activity type (``kind``), which the shared
    domain would otherwise keep; a type already deprecated or gone is fine."""
    arg = {"workflow": "workflowType", "activity": "activityType"}[kind]
    try:
        getattr(swf, f"deprecate_{kind}_type")(domain=domain, **{arg: type_ref})
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("TypeDeprecatedFault", "UnknownResourceFault"):
            raise
    try:
        getattr(swf, f"delete_{kind}_type")(domain=domain, **{arg: type_ref})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
