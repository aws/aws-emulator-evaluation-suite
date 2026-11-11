"""explicit-deny-blocks-every-states-api."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "explicit-deny-blocks-every-states-api"
GROUP = "authorization-denial"
SERVICES = ["stepfunctions"]

_STATES_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_DEFINITION_TEMPLATE = {
    "StartAt": "DoActivity",
    "States": {"DoActivity": {"Type": "Task", "Resource": None, "End": True}},
}
_SESSION_NAME = "sim2real-behav-denied"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An identity-based explicit Deny on states:* refuses every management, execution and
    activity-task API with AccessDeniedException, naming the caller, the action and the
    resource, never only a subset of the surface; a sibling role without the deny still succeeds.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/security_iam_troubleshoot.html
    """
    sfn = ctx.client("stepfunctions")
    account = ctx.account

    exec_role_arn = _create_role(ctx, "sim2real-behav-execrole-", _STATES_TRUST)
    activity_arn = sfn.create_activity(name=ctx.unique_name("sim2real-behav-act-"))["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    definition = json.loads(json.dumps(_DEFINITION_TEMPLATE))
    definition["States"]["DoActivity"]["Resource"] = activity_arn
    sm_arn = _create_state_machine(ctx, exec_role_arn, definition)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    token = _poll_for_task_token(sfn, activity_arn, timeout_s=60.0)
    ctx.on_cleanup(lambda: _best_effort_finish(sfn, token))

    fake_exec_arn = exec_arn.rsplit(":", 1)[0] + ":" + ctx.unique_name("sim2real-behav-fakeexec-")
    create_sm_name = ctx.unique_name("sim2real-behav-createsm-")
    create_activity_name = ctx.unique_name("sim2real-behav-createact-")

    caller_arn = _create_role(
        ctx, "sim2real-behav-denyall-",
        json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": account}, "Action": "sts:AssumeRole"}]}),
        statements=[
            {"Effect": "Allow", "Action": "states:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "states:*", "Resource": "*"},
        ],
    )
    denied = _assume_as_client(ctx, "stepfunctions", caller_arn)
    caller_identity = f"arn:aws:sts::{account}:assumed-role/{caller_arn.rsplit('/', 1)[-1]}/{_SESSION_NAME}"
    definition_before = sfn.describe_state_machine(stateMachineArn=sm_arn)["definition"]

    cases = [
        ("ListStateMachines", lambda: denied.list_state_machines(),
         f"arn:aws:states:{ctx.region}:{account}:stateMachine:*"),
        ("ListActivities", lambda: denied.list_activities(),
         f"arn:aws:states:{ctx.region}:{account}:activity:*"),
        ("ListExecutions", lambda: denied.list_executions(stateMachineArn=sm_arn), sm_arn),
        ("ListTagsForResource", lambda: denied.list_tags_for_resource(resourceArn=sm_arn), sm_arn),
        ("DescribeStateMachine", lambda: denied.describe_state_machine(stateMachineArn=sm_arn), sm_arn),
        ("UpdateStateMachine",
         lambda: denied.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(definition)),
         sm_arn),
        ("DeleteStateMachine", lambda: denied.delete_state_machine(stateMachineArn=sm_arn), sm_arn),
        ("TagResource",
         lambda: denied.tag_resource(resourceArn=sm_arn, tags=[{"key": "k", "value": "v"}]), sm_arn),
        ("UntagResource", lambda: denied.untag_resource(resourceArn=sm_arn, tagKeys=["k"]), sm_arn),
        ("CreateStateMachine",
         lambda: denied.create_state_machine(
             name=create_sm_name, definition=json.dumps(definition), roleArn=exec_role_arn),
         f"arn:aws:states:{ctx.region}:{account}:stateMachine:{create_sm_name}"),
        ("CreateActivity", lambda: denied.create_activity(name=create_activity_name),
         f"arn:aws:states:{ctx.region}:{account}:activity:{create_activity_name}"),
        ("StartExecution", lambda: denied.start_execution(stateMachineArn=sm_arn), sm_arn),
        ("DescribeExecution", lambda: denied.describe_execution(executionArn=fake_exec_arn), fake_exec_arn),
        ("GetExecutionHistory", lambda: denied.get_execution_history(executionArn=fake_exec_arn),
         fake_exec_arn),
        ("RedriveExecution", lambda: denied.redrive_execution(executionArn=fake_exec_arn), fake_exec_arn),
        ("StopExecution", lambda: denied.stop_execution(executionArn=fake_exec_arn), fake_exec_arn),
        ("DescribeStateMachineForExecution",
         lambda: denied.describe_state_machine_for_execution(executionArn=fake_exec_arn), fake_exec_arn),
        ("DescribeActivity", lambda: denied.describe_activity(activityArn=activity_arn), activity_arn),
        ("DeleteActivity", lambda: denied.delete_activity(activityArn=activity_arn), activity_arn),
        ("GetActivityTask", lambda: denied.get_activity_task(activityArn=activity_arn), activity_arn),
        ("SendTaskHeartbeat", lambda: denied.send_task_heartbeat(taskToken=token), activity_arn),
        ("SendTaskFailure", lambda: denied.send_task_failure(taskToken=token), activity_arn),
        ("SendTaskSuccess", lambda: denied.send_task_success(taskToken=token, output="{}"), activity_arn),
    ]
    for op, call, resource in cases:
        code, message = _error(call)
        assert code == "AccessDeniedException", f"{op}: expected AccessDeniedException, got {code!r}"
        expected = (
            f"User: {caller_identity} is not authorized to perform: states:{op} on resource: "
            f"{resource} with an explicit deny in an identity-based policy"
        )
        assert message == expected, f"{op}: message was {message!r}, expected {expected!r}"

    # Effect absent: none of the denied calls mutated anything the still-valid execution role or
    # resources could show.
    desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert desc["definition"] == definition_before, "the denied UpdateStateMachine must not land"
    assert sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING", (
        "the denied StopExecution must not have aborted the outstanding execution"
    )

    # Positive control: a sibling role with no deny performs the identical call successfully.
    allowed_arn = _create_role(
        ctx, "sim2real-behav-allow-",
        json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": account}, "Action": "sts:AssumeRole"}]}),
        statements=[{"Effect": "Allow", "Action": "states:ListStateMachines", "Resource": "*"}],
    )
    allowed = _assume_as_client(ctx, "stepfunctions", allowed_arn)
    listing = _retry_while_denied(lambda: allowed.list_state_machines())
    names = {sm["name"] for sm in listing["stateMachines"]}
    assert any(sm_arn.endswith(":" + n) for n in names), (
        f"the sibling role without a deny could not list the state machine it owns: {sorted(names)}"
    )


def _create_role(ctx, prefix, trust_policy, *, statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name, PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90
    arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
            )["stateMachineArn"]
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            time.sleep(3)
    if arn is None:
        raise AssertionError(f"create_state_machine never succeeded: {last_err!r}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _poll_for_task_token(sfn, activity_arn, *, timeout_s=60.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = sfn.get_activity_task(activityArn=activity_arn)
        if task.get("taskToken"):
            return task["taskToken"]
        time.sleep(interval_s)
    raise AssertionError(f"no activity task queued within {timeout_s}s")


def _best_effort_finish(sfn, token):
    try:
        sfn.send_task_success(taskToken=token, output="{}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TaskTimedOut":
            raise


def _assume_as_client(ctx, service, role_arn, *, timeout_s=90.0):
    """A ctx client signed with role_arn's credentials. A just-minted STS session can be
    rejected by other services for a few seconds after STS itself accepts it; that warm-up
    is retried on its one documented code before the client is handed back."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            last = exc
            time.sleep(3)
            continue
        boto_creds = {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        }
        warmup = ctx.client("sts", creds=boto_creds)
        while time.monotonic() < deadline:
            try:
                warmup.get_caller_identity()
                return ctx.client(service, creds=boto_creds)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "UnrecognizedClientException":
                    raise
                last = exc
                time.sleep(2)
    raise AssertionError(f"could not assume {role_arn!r} within {timeout_s}s: {last!r}")


def _retry_while_denied(fn, *, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"still denied after {timeout_s}s of IAM propagation: {last!r}")


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) ``fn`` raised; raises if ``fn`` unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"call was expected to be refused but SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
