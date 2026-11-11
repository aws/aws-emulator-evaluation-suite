"""denied-states-action-names-resource-by-api-category."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "denied-states-action-names-resource-by-api-category"
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
_SESSION_NAME = "sim2real-behav-noperm"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A caller with no states permissions is denied naming the resource its own request
    scoped: List* names a resource-type wildcard, a non-StartExecution execution call
    names the execution ARN, and an activity-token call names the issuing activity's ARN.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/security_iam_troubleshoot.html
    """
    sfn = ctx.client("stepfunctions")
    account = ctx.account

    exec_role_arn = _create_role(ctx, "sim2real-behav-execrole-", _STATES_TRUST)
    activity_arn = sfn.create_activity(name=ctx.unique_name("sim2real-behav-act-"))["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    definition = {
        "StartAt": "DoActivity",
        "States": {"DoActivity": {"Type": "Task", "Resource": activity_arn, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, exec_role_arn, definition)
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    token = _poll_for_task_token(sfn, activity_arn, timeout_s=60.0)
    ctx.on_cleanup(lambda: _best_effort_finish(sfn, token))

    noperm_arn = _create_role(
        ctx, "sim2real-behav-noperm-",
        json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": account}, "Action": "sts:AssumeRole"}]}),
    )
    denied = _assume_as_client(ctx, "stepfunctions", noperm_arn)
    caller_identity = f"arn:aws:sts::{account}:assumed-role/{noperm_arn.rsplit('/', 1)[-1]}/{_SESSION_NAME}"

    def expect(op, call, resource):
        code, message = _error(call)
        assert code == "AccessDeniedException", f"{op}: expected AccessDeniedException, got {code!r}"
        expected = (
            f"User: {caller_identity} is not authorized to perform: states:{op} on resource: "
            f"{resource} because no identity-based policy allows the states:{op} action"
        )
        assert message == expected, f"{op}: message was {message!r}, expected {expected!r}"

    # List* names the wildcard of its resource type, never the caller's own resources.
    expect("ListStateMachines", lambda: denied.list_state_machines(),
           f"arn:aws:states:{ctx.region}:{account}:stateMachine:*")
    expect("ListActivities", lambda: denied.list_activities(),
           f"arn:aws:states:{ctx.region}:{account}:activity:*")

    # A non-StartExecution execution call names the execution ARN, not the state machine.
    expect("DescribeExecution", lambda: denied.describe_execution(executionArn=exec_arn), exec_arn)
    expect("GetExecutionHistory", lambda: denied.get_execution_history(executionArn=exec_arn), exec_arn)
    expect("StopExecution", lambda: denied.stop_execution(executionArn=exec_arn), exec_arn)
    expect("RedriveExecution", lambda: denied.redrive_execution(executionArn=exec_arn), exec_arn)
    expect("DescribeStateMachineForExecution",
           lambda: denied.describe_state_machine_for_execution(executionArn=exec_arn), exec_arn)

    # GetActivityTask and SendTask* carrying a real activity-issued token name the activity ARN
    # the token came from -- the same operations a Lambda waitForTaskToken callback would instead
    # authorize against the state machine ARN, because that token names no activity at all.
    expect("GetActivityTask", lambda: denied.get_activity_task(activityArn=activity_arn), activity_arn)
    expect("SendTaskHeartbeat", lambda: denied.send_task_heartbeat(taskToken=token), activity_arn)
    expect("SendTaskFailure", lambda: denied.send_task_failure(taskToken=token), activity_arn)
    expect("SendTaskSuccess", lambda: denied.send_task_success(taskToken=token, output="{}"), activity_arn)

    # Effect absent: the execution is untouched by the denied StopExecution/RedriveExecution calls.
    assert sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING", (
        "a denied StopExecution/RedriveExecution must not have changed the execution's status"
    )

    # Positive control: the same token, used by a caller actually granted the permission, resumes
    # the execution -- proving the denial above was the missing permission, not a broken token.
    sfn.send_task_success(taskToken=token, output="{}")
    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0, description="execution to leave RUNNING",
    )
    assert final["status"] == "SUCCEEDED", f"the permitted SendTaskSuccess did not resolve it: {final}"


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
        if exc.response["Error"]["Code"] not in ("TaskTimedOut", "TaskDoesNotExist", "InvalidToken"):
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


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
