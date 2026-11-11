"""cdk-deploy-role-arn-stays-the-stacks-role-for-later-deploys."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-role-arn-stays-the-stacks-role-for-later-deploys"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "sqs", "ssm"]

_APP = "cdk_role_arn"
_ASSUME_BUDGET_S = 90.0


@tags("axis:happy-path", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --role-arn` with an ssm-only role creates the parameter and records the role;
    a later deploy without the flag still acts as that role, so adding a queue fails, naming the
    role, and rolls back with the role and the parameter intact.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    role = ctx.unique_name("sim2real-cdk-rolearn-")
    stack = ctx.unique_name("sim2real-cdk-rolearn-")
    param = "/" + ctx.unique_name("sim2real-cdk-rolearn-")
    queue = ctx.unique_name("sim2real-cdk-rolearn-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "param_name": param, "queue_name": queue}
    work = _stage_app(ctx)

    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role), "NoSuchEntity"))
    iam.put_role_policy(RoleName=role, PolicyName="exec", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ssm:*", "Resource": "*"}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role, PolicyName="exec"),
                             "NoSuchEntity"))
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=param), "ParameterNotFound"))
    ctx.on_cleanup(_teardown(lambda: _delete_queue(sqs, queue),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    deadline = time.monotonic() + _ASSUME_BUDGET_S
    while True:
        rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--role-arn", arn],
                       {**context, "with_queue": "0"})
        # IAM propagation: CloudFormation cannot assume a role created seconds ago.
        if rc == 0 or f"Role {arn} is invalid or cannot be assumed" not in out:
            break
        if time.monotonic() > deadline:
            break
        _delete_stack(cfn, stack)
        time.sleep(3.0)
    assert rc == 0, f"`cdk deploy --role-arn` exited {rc}; output tail {out[-800:]!r}"
    first = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = first["StackId"]
    assert (first["StackStatus"], first.get("RoleARN")) == ("CREATE_COMPLETE", arn), (
        f"after `cdk deploy --role-arn` the stack is {first['StackStatus']!r} with RoleARN "
        f"{first.get('RoleARN')!r}"
    )
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value == "made-by-role", f"the role-created parameter holds {value!r}"

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**context, "with_queue": "1"})
    assert rc == 1, f"the deploy adding a queue exited {rc}; output tail {out[-800:]!r}"
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert (after["StackStatus"], after.get("RoleARN")) == ("UPDATE_ROLLBACK_COMPLETE", arn), (
        f"the deploy without --role-arn left {after['StackStatus']!r} with RoleARN "
        f"{after.get('RoleARN')!r}"
    )
    failed = [e.get("ResourceStatusReason") or "" for e in _events(cfn, stack_id)
              if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Queue", "CREATE_FAILED")]
    assert len(failed) == 1, f"expected one CREATE_FAILED event for the queue, got {failed!r}"
    pattern = (
        r'Resource handler returned message: "User: '
        + re.escape(f"arn:aws:sts::{ctx.account}:assumed-role/{role}/")
        + r"[\w+=,.@-]+ is not authorized to perform: sqs:createqueue on resource: "
        + re.escape(f"arn:aws:sqs:{ctx.region}:{ctx.account}:{queue}")
        + r" because no identity-based policy allows the sqs:createqueue action \(Service: Sqs, "
        r"Status Code: 403, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)\" "
        r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: AccessDenied\)"
    )
    assert re.fullmatch(pattern, failed[0]), f"the queue failed with {failed[0]!r}"
    gone = _err(lambda: sqs.get_queue_url(QueueName=queue))
    assert gone == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the queue the stack role could not create answers {gone!r}"
    )
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value == "made-by-role", f"the rolled-back stack's parameter holds {value!r}"


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out stays out of the app directory."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *,
         timeout_s: float = 600.0) -> tuple[int, str]:
    """Run the CDK CLI against the target; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color",
           "--no-notices", "--no-version-reporting"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_queue(sqs, name: str) -> None:
    sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=name)["QueueUrl"])


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
