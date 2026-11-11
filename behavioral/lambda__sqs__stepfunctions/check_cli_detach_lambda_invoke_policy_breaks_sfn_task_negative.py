"""cli-detach-lambda-invoke-policy-breaks-sfn-task-negative."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-detach-lambda-invoke-policy-breaks-sfn-task-negative"
GROUP = "cli-workflow"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda Task succeeds and invokes the function while the SFN role has lambda:InvokeFunction;
    after detach-role-policy it fails with Lambda.AWSLambdaException (403, not authorized) and
    the function is not invoked; re-attaching the policy makes it succeed again."""
    require_tools("aws")

    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")
    sqs = ctx.client("sqs")

    tag_kv = {"sim2real-check": CHECK}

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-detach-signal-"),
        Attributes={"VisibilityTimeout": "5"},
        tags=tag_kv,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    lambda_role_name = ctx.unique_name("sim2real-detach-lrole-")
    lambda_role_arn = iam.create_role(
        RoleName=lambda_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(iam, lambda_role_name))
    iam.attach_role_policy(RoleName=lambda_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    iam.put_role_policy(
        RoleName=lambda_role_name,
        PolicyName="signal-queue-send",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
        }),
    )
    _wait_role_assumable(iam, lambda_role_name)

    function_name = ctx.unique_name("sim2real-detach-fn-")
    handler_code = (
        "import json, os\n"
        "import boto3\n"
        "def handler(event, context):\n"
        "    boto3.client('sqs').send_message(QueueUrl=os.environ['SIGNAL_QUEUE_URL'], MessageBody='invoked')\n"
        "    return {'ok': True}\n"
    )
    zip_path = _write_zip(handler_code)
    try:
        function_arn = _create_function_with_retry(
            lam, function_name, lambda_role_arn, zip_path,
            env={"SIGNAL_QUEUE_URL": queue_url}, tags=tag_kv,
        )
    finally:
        os.unlink(zip_path)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    sfn_role_name = ctx.unique_name("sim2real-detach-srole-")
    sfn_role_arn = iam.create_role(
        RoleName=sfn_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_fully(iam, sfn_role_name))

    policy_name = ctx.unique_name("sim2real-detach-invoke-policy-")
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn}],
        }),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    iam.attach_role_policy(RoleName=sfn_role_name, PolicyArn=policy_arn)
    _wait_role_assumable(iam, sfn_role_name)
    _wait_policy_attached(iam, sfn_role_name, policy_arn)

    sm_name = ctx.unique_name("sim2real-detach-sm-")
    definition = json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {"Type": "Task", "Resource": function_arn, "End": True}},
    })
    sm_arn = _create_state_machine_with_retry(
        sfn, sm_name, definition, sfn_role_arn,
        tags_list=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    # positive control: with the policy attached, the task state succeeds. IAM policy
    # attachment is eventually consistent for other services evaluating the permission (can
    # lag tens of seconds after list-attached-role-policies already shows it), so retry fresh
    # executions until one succeeds or the retry budget is exhausted. The Lambda handler's own
    # role permission to reach the signal queue is subject to the same eventual consistency, and
    # a failure there also just fails the task state, so the same retry naturally rides it out.
    result1 = None
    exec1_started_at = None
    retry_deadline = time.monotonic() + 90.0
    while time.monotonic() < retry_deadline:
        exec1_started_at = time.monotonic()
        exec1_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        result1 = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec1_arn),
            lambda r: r["status"] != "RUNNING", timeout_s=60.0, interval_s=2.0,
        )
        if result1["status"] == "SUCCEEDED":
            break
        time.sleep(5)
    assert result1["status"] == "SUCCEEDED", f"positive control failed: {result1.get('status')} {result1.get('cause')}"

    # independent read at the consumer: the positive control must have actually invoked the
    # Lambda function, not merely reported success from Step Functions' own side.
    signal1 = _receive_one(sqs, queue_url, timeout_s=45.0)
    assert signal1 is not None, "positive control succeeded but no invocation signal arrived at the queue"
    positive_signal_latency_s = max(time.monotonic() - exec1_started_at, 1.0)
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=signal1["ReceiptHandle"])

    # break: detach the invoke permission via the CLI
    _run_aws(ctx, "iam", "detach-role-policy", "--role-name", sfn_role_name, "--policy-arn", policy_arn)
    _wait_policy_detached(iam, sfn_role_name, policy_arn)

    # IAM policy detachment is also eventually consistent for other services evaluating the
    # permission (can lag tens of seconds after list-attached-role-policies already shows it
    # gone), so retry fresh executions until one actually fails.
    result2 = None
    retry_deadline = time.monotonic() + 90.0
    while time.monotonic() < retry_deadline:
        exec2_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        result2 = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec2_arn),
            lambda r: r["status"] != "RUNNING", timeout_s=60.0, interval_s=2.0,
        )
        transient = result2.get("error") == "States.TaskFailed" and (
            "is not authorized to assume the provided role" in str(result2.get("cause", ""))
        )
        # While the role change propagates, Step Functions can briefly fail to assume the role
        # at all; that is IAM lag, not the invoke refusal under test, so it is retried too.
        if result2["status"] == "FAILED" and not transient:
            break
        time.sleep(5)
    assert result2["status"] == "FAILED", f"expected FAILED after detaching invoke permission, got {result2['status']}"
    assert result2.get("error") == "Lambda.AWSLambdaException", (
        f"expected Lambda.AWSLambdaException, got: {result2.get('error')} {result2.get('cause')}"
    )
    # message varies: the cause ("User: <assumed-role arn>/<session> is not authorized to perform:
    # lambda:InvokeFunction ... (Service: Lambda, Status Code: 403, Request ID: <id>)") carries a
    # session name Step Functions chooses and a per-call Lambda Request ID, so its stable
    # parts are graded.
    cause = str(result2.get("cause", ""))
    assert cause.startswith("User: arn:aws:sts::"), f"expected an authorization failure, got: {cause}"
    assert f":assumed-role/{sfn_role_name}/" in cause, f"expected the state machine role, got: {cause}"
    assert "is not authorized to perform: lambda:InvokeFunction" in cause, (
        f"expected an authorization failure, got: {cause}"
    )
    assert "Status Code: 403" in cause, f"expected a 403 authorization failure, got: {cause}"

    # the retry loop above may have run one or more fresh executions before permission
    # detachment fully propagated, and any of those transitional successes would have invoked
    # the Lambda and left a stray signal in the queue. Drain those now, before measuring the
    # negative window — they are evidence of exactly the lag the loop above already tolerates,
    # not evidence against the FAILED result just asserted.
    stray = _receive_one(sqs, queue_url, timeout_s=3.0)
    while stray is not None:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=stray["ReceiptHandle"])
        stray = _receive_one(sqs, queue_url, timeout_s=3.0)

    # effect absent, at the consumer: hold for a calibrated window (>=3x the positive control's
    # own signal latency, measured on this same wiring in this same run), repeatedly polling with
    # real receives rather than trusting SQS's own ApproximateNumberOfMessages — that attribute is
    # itself eventually consistent and was still showing the just-deleted positive-control signal
    # seconds after the delete, which is not a second invocation.
    absence_window_s = min(max(positive_signal_latency_s * 3.0, 15.0), 90.0)
    deadline = time.monotonic() + absence_window_s
    polls = 0
    while time.monotonic() < deadline:
        wait_s = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_s)
        polls += 1
        absent_signal = resp.get("Messages", [None])[0] if resp.get("Messages") else None
        assert absent_signal is None, (
            f"expected no invocation signal while the invoke permission was detached, got {absent_signal}"
        )
    assert polls >= 2, f"absence window too short to poll more than once: {polls} poll(s)"

    # restore: re-attach the identical policy and demand the identical call succeed again, proven
    # the same independent way.
    iam.attach_role_policy(RoleName=sfn_role_name, PolicyArn=policy_arn)
    _wait_policy_attached(iam, sfn_role_name, policy_arn)

    result3 = None
    retry_deadline = time.monotonic() + 90.0
    while time.monotonic() < retry_deadline:
        exec3_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        result3 = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec3_arn),
            lambda r: r["status"] != "RUNNING", timeout_s=60.0, interval_s=2.0,
        )
        if result3["status"] == "SUCCEEDED":
            break
        time.sleep(5)
    assert result3["status"] == "SUCCEEDED", (
        f"expected the identical call to succeed again after re-attaching the policy, "
        f"got {result3.get('status')} {result3.get('cause')}"
    )
    signal3 = _receive_one(sqs, queue_url, timeout_s=45.0)
    assert signal3 is not None, "policy was re-attached and the task succeeded, but no invocation signal arrived at the queue"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=signal3["ReceiptHandle"])

    # leave the policy detached again so final cleanup (which deletes the customer policy before
    # detaching it from the role, LIFO) does not hit DeleteConflict.
    iam.detach_role_policy(RoleName=sfn_role_name, PolicyArn=policy_arn)


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _wait_role_assumable(iam_client, role_name, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam_client.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(2)
    raise AssertionError(f"role {role_name} never became visible")


def _wait_policy_attached(iam_client, role_name, policy_arn, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = [p["PolicyArn"] for p in iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]
        if policy_arn in arns:
            return
        time.sleep(2)
    raise AssertionError(f"policy {policy_arn} never showed attached to {role_name}")


def _wait_policy_detached(iam_client, role_name, policy_arn, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        arns = [p["PolicyArn"] for p in iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]
        if policy_arn not in arns:
            return
        time.sleep(2)
    raise AssertionError(f"policy {policy_arn} never showed detached from {role_name}")


def _delete_role_fully(iam_client, role_name):
    try:
        for pname in iam_client.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam_client.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam_client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam_client.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _write_zip(handler_code: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def _create_function_with_retry(lambda_client, name, role_arn, zip_path, env=None, tags=None, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    with open(zip_path, "rb") as f:
        zip_bytes = f.read()
    kwargs = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler", Code={"ZipFile": zip_bytes}, Timeout=30, MemorySize=128,
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    if tags is not None:
        kwargs["Tags"] = tags
    while time.monotonic() < deadline:
        try:
            resp = lambda_client.create_function(**kwargs)
            lambda_client.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return resp["FunctionArn"]
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_function never succeeded: {last_err}")


def _create_state_machine_with_retry(sfn_client, name, definition, role_arn, tags_list=None, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = dict(name=name, definition=definition, roleArn=role_arn)
    if tags_list is not None:
        kwargs["tags"] = tags_list
    while time.monotonic() < deadline:
        try:
            return sfn_client.create_state_machine(**kwargs)["stateMachineArn"]
        except Exception as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_state_machine never succeeded: {last_err}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _receive_one(sqs_client, queue_url, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait_s = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_s)
        msgs = resp.get("Messages", [])
        if msgs:
            return msgs[0]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
