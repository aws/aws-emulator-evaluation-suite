"""deep-sfn-1-sfn-sync-lambda-invoke-envelope-vs-raw-arn-bare-payload."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-1-sfn-sync-lambda-invoke-envelope-vs-raw-arn-bare-payload"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']

_HANDLER = (
    "def lambda_handler(event, context):\n"
    "    return {'echo': event.get('v'), 'n': 7}\n"
)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A raw function ARN Resource returns the bare payload as a LambdaFunction* state, while
    arn:aws:states:::lambda:invoke wraps the same payload in {Payload, StatusCode, ...} and
    records Task* events with resourceType lambda."""
    fn_arn = _create_lambda(ctx, {"lambda_function.py": _HANDLER}, runtime="python3.12",
                            handler="lambda_function.lambda_handler", timeout=10)
    role_arn = _lambda_sfn_role(ctx, fn_arn)
    sm_arn = _create_state_machine(ctx, {
        "Comment": "same function, raw ARN form then optimized lambda:invoke form",
        "StartAt": "Raw",
        "States": {
            "Raw": {
                "Type": "Task",
                "Resource": fn_arn,
                "Parameters": {"v.$": "$.v"},
                "ResultPath": "$.raw",
                "Next": "Envelope",
            },
            "Envelope": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload": {"v.$": "$.v"}},
                "ResultPath": "$.env",
                "End": True,
            },
        },
    }, role_arn)

    v = ctx.unique_name("v-")
    bare = {"echo": v, "n": 7}
    desc = _run_to_terminal(ctx, sm_arn, {"v": v})
    assert desc["status"] == "SUCCEEDED", (
        f"the execution ended {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
    )
    out = json.loads(desc["output"])
    assert out["raw"] == bare, (
        f"the raw-ARN form returned {out['raw']!r}, expected the bare payload {bare!r}"
    )
    env = out["env"]
    missing = {"Payload", "StatusCode", "ExecutedVersion", "SdkHttpMetadata",
               "SdkResponseMetadata"} - set(env)
    assert not missing, f"the lambda:invoke envelope lacks {sorted(missing)!r}: {env!r}"
    assert env["Payload"] == bare, (
        f"the envelope's Payload was {env['Payload']!r}, expected {bare!r}"
    )
    assert env["StatusCode"] == 200 and env["ExecutedVersion"] == "$LATEST", (
        f"envelope StatusCode/ExecutedVersion were {env['StatusCode']!r}/"
        f"{env['ExecutedVersion']!r}"
    )
    assert env["SdkHttpMetadata"].get("HttpStatusCode") == 200, (
        f"SdkHttpMetadata was {env['SdkHttpMetadata']!r}"
    )

    events = _history(ctx, desc["executionArn"])
    types = [e["type"] for e in events]
    raw_ok = [e["lambdaFunctionSucceededEventDetails"] for e in events
              if e["type"] == "LambdaFunctionSucceeded"]
    assert len(raw_ok) == 1 and json.loads(raw_ok[0]["output"]) == bare, (
        f"the raw-ARN state's LambdaFunctionSucceeded events were {raw_ok!r}"
    )
    scheduled = [e["lambdaFunctionScheduledEventDetails"] for e in events
                 if e["type"] == "LambdaFunctionScheduled"]
    assert len(scheduled) == 1 and scheduled[0]["resource"] == fn_arn, (
        f"LambdaFunctionScheduled events were {scheduled!r}"
    )
    task_ok = [e["taskSucceededEventDetails"] for e in events if e["type"] == "TaskSucceeded"]
    assert len(task_ok) == 1 and task_ok[0]["resourceType"] == "lambda" and \
        task_ok[0]["resource"] == "invoke", f"TaskSucceeded events were {task_ok!r}"
    assert json.loads(task_ok[0]["output"])["Payload"] == bare, (
        f"the optimized task's recorded output was {task_ok[0]['output']!r}"
    )
    assert types.count("TaskScheduled") == 1, f"history was {types!r}"


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=150, attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        arn = _start(ctx, sm_arn, payload)
        desc = _poll(lambda: sfn.describe_execution(executionArn=arn),
                     lambda d: d["status"] in _TERMINAL, timeout_s=timeout_s,
                     what=f"execution {arn} terminal")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "States.Permissions",
    "AccessDeniedException",
)


def _account(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, principal, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnsync-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn sync execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    # IAM propagation exposes no condition to poll; the bounded retries at first use
    # (_create_state_machine, _start_parent_until_child) absorb it.
    return role_arn


def _sync_role(ctx, child_names):
    account = _account(ctx)
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": [f"arn:aws:states:{ctx.region}:{account}:stateMachine:{n}"
                      for n in child_names]},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": [f"arn:aws:states:{ctx.region}:{account}:execution:{n}:*"
                      for n in child_names]},
        {"Effect": "Allow", "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
         "Resource": f"arn:aws:events:{ctx.region}:{account}:rule/"
                     "StepFunctionsGetEventsForStepFunctionsExecutionRule"},
    ])


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sync-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _start(ctx, sm_arn, payload=None):
    arn = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload or {}),
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


def _poll(probe, predicate, *, timeout_s, what, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


def _start_parent_until_child(ctx, parent_arn, payload=None, *, attempts=6):
    """Start the parent and return (parent, child) once its .sync task has started the child.

    The .sync task is the first runtime use of the role, so an unpropagated policy fails the
    parent with a permissions error; that — and only that — earns a fresh attempt.
    """
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        parent = _start(ctx, parent_arn, payload)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for ev in _history(ctx, parent):
                if ev["type"] == "TaskSubmitted":
                    child = json.loads(ev["taskSubmittedEventDetails"]["output"])["ExecutionArn"]
                    ctx.on_cleanup(lambda a=child: _best_effort_stop(ctx, a))
                    return parent, child
            desc = sfn.describe_execution(executionArn=parent)
            if desc["status"] in _TERMINAL:
                break
            time.sleep(1.0)
        else:
            raise AssertionError(f"parent {parent} never submitted its child within 60s")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            raise AssertionError(
                f"parent ended {desc['status']!r} before starting its child: "
                f"{desc.get('error')!r} {desc.get('cause')!r}")
        time.sleep(5)
    raise AssertionError(f"the parent's role never propagated: {desc!r}")



def _lambda_sfn_role(ctx, fn_arn):
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction",
         "Resource": [fn_arn, f"{fn_arn}:*"]},
    ])


def _reap_log_group(ctx, name):
    """Delete the function's log group and keep deleting until it stays gone.

    The function's role grants no logs permissions, so the group should never exist; this is
    the net for the case where it does. A buffered flush can recreate it after one delete, so
    one call is one round, not a teardown.
    """
    logs = ctx.client("logs")
    absent_rounds = 0
    for _ in range(8):
        try:
            logs.delete_log_group(logGroupName=name)
            absent_rounds = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            absent_rounds += 1
            if absent_rounds >= 2:
                return
        time.sleep(2)
    raise RuntimeError(f"log group {name} kept reappearing")


def _create_lambda(ctx, files, *, runtime, handler, timeout):
    import io
    import zipfile

    lam = ctx.client("lambda")
    role_arn = _create_role(ctx, "lambda.amazonaws.com", [])
    fn_name = ctx.unique_name("sim2real-behav-syncfn-")
    # Registered BEFORE the create, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, body in files.items():
            zf.writestr(path, body)
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=fn_name, Runtime=runtime, Role=role_arn, Handler=handler,
                Code={"ZipFile": buf.getvalue()}, Timeout=timeout, MemorySize=128,
                Description="sim2real-behav sfn task target", Tags={"sim2real": CHECK},
            )["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
            break
        except ClientError as exc:
            # IAM propagation of the new role: the only retried failure.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" \
                    or "assume" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)
    _poll(lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
          lambda s: s == "Active", timeout_s=90, what=f"function {fn_name} Active")
    return arn

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
