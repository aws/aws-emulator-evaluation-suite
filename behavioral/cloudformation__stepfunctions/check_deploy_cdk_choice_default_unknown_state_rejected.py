"""deploy-cdk-choice-default-unknown-state-rejected."""
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

CHECK = "deploy-cdk-choice-default-unknown-state-rejected"
GROUP = "deploy-cdk"
SERVICES = ["cloudformation", "stepfunctions"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_ID = r"[A-Za-z0-9-]+"
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: ' + _ID + r'\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: ' + _ID + r', HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)

_APP_PY = '''\
import json
import os
import aws_cdk as cdk
from aws_cdk import aws_stepfunctions as sfn

fix = os.environ.get("FIX") == "1"

definition = {
    "StartAt": "CheckTotal",
    "States": {
        "CheckTotal": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.total", "NumericGreaterThan": 1000, "Next": "Rejected"}],
            "Default": "Accepted" if fix else "NoSuchState",
        },
        "Rejected": {"Type": "Fail", "Error": "OrderRejected",
                     "Cause": "the order total exceeded the approval limit"},
    },
}
if fix:
    definition["States"]["Accepted"] = {"Type": "Succeed"}


class ChoiceDefaultStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        machine = sfn.StateMachine(
            self, "Machine",
            definition_body=sfn.DefinitionBody.from_string(json.dumps(definition)),
            timeout=cdk.Duration.minutes(2),
        )
        cdk.CfnOutput(self, "StateMachineArn", value=machine.state_machine_arn)


app = cdk.App()
ChoiceDefaultStack(app, os.environ["STACK_NAME"],
                    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
                    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                                        region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()
'''


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A `cdk deploy` of a state machine whose Choice Default names an absent state fails with
    Step Functions' MISSING_TRANSITION_TARGET and rolls back to nothing; the same stack, fixed to
    name a real state, deploys and routes both branches.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-choice-state.html
    """
    require_tools("cdk")
    ctx.verify_account_safety()
    acct = ctx.account
    cfn = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkbaddflt-")

    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkbaddflt-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    (work / "app.py").write_text(_APP_PY)

    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    _bootstrap(ctx, qualifier, toolkit)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, staging))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, toolkit))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

    # 1. The broken definition: Default names a state the machine does not have.
    rc, out = _cdk(ctx, work, ["deploy"], qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S,
                   expect_rc=None, fix=False)
    assert rc != 0, f"`cdk deploy` exited 0 with a Choice Default naming a nonexistent state: {out[-1200:]!r}"

    failed = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert failed["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"the rejected create left stack status {failed['StackStatus']!r}, expected ROLLBACK_COMPLETE"
    )
    events = _events(cfn, failed["StackId"])
    machine_failed = [e for e in events
                      if e["ResourceType"] == "AWS::StepFunctions::StateMachine"
                      and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(machine_failed) == 1, (
        f"expected one CREATE_FAILED event for the state machine, got {machine_failed!r}"
    )
    reason = machine_failed[0].get("ResourceStatusReason") or ""
    match = _REASON.match(reason)
    assert match is not None, f"the state machine's CREATE_FAILED reason is not a handler message: {reason!r}"
    got = (match["message"], match["service"], match["status"], match["handler"])
    want = (
        "Invalid State Machine Definition: 'MISSING_TRANSITION_TARGET: Missing 'Next' target: "
        "NoSuchState at /States/CheckTotal/Default'",
        "Sfn",
        "400",
        "InvalidRequest",
    )
    assert got == want, f"the state machine's CREATE_FAILED reason: expected {want!r}, got {got!r}"
    assert machine_failed[0].get("PhysicalResourceId") in (None, ""), (
        f"a state machine was minted despite the rejected create: "
        f"{machine_failed[0].get('PhysicalResourceId')!r}"
    )
    # The rollback removed the execution role the failed create had already built.
    rolled_back_roles = sorted({e["PhysicalResourceId"] for e in events
                                if e["ResourceType"] == "AWS::IAM::Role"
                                and e["ResourceStatus"] == "CREATE_COMPLETE"})
    assert rolled_back_roles, f"the failed create built no execution role: {events!r}"
    _assert_roles_gone(ctx.client("iam"), rolled_back_roles)

    # 2. CONTROL: the identical stack, fixed to a real Default target, deploys and runs.
    rc, out = _cdk(ctx, work, ["deploy"], qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S,
                   expect_rc=0, fix=True)
    sm_arn = _stack_outputs(cfn, stack)["StateMachineArn"]
    roles = _stack_physical_ids(cfn, stack, "AWS::IAM::Role")
    assert roles, f"stack {stack!r} declares no execution role"

    good = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("ok-"), input=json.dumps({"total": 500})
    )
    bad = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("no-"), input=json.dumps({"total": 5000})
    )
    ok = _terminal(sfn, good["executionArn"])
    no = _terminal(sfn, bad["executionArn"])
    assert ok["status"] == "SUCCEEDED", (
        f"control: under-limit execution ended {ok['status']!r}, expected SUCCEEDED"
    )
    assert no["status"] == "FAILED" and no["error"] == "OrderRejected", (
        f"control: over-limit execution ended status={no.get('status')!r} error={no.get('error')!r}, "
        f"expected FAILED with error OrderRejected"
    )

    # `cdk destroy` in-band is the graded teardown path.
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S,
         expect_rc=0, fix=True)

    stack_err = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert stack_err == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after `cdk destroy` returned {stack_err!r}"
    )
    sfn_err = _error(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert sfn_err == ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{sm_arn}'"), (
        f"the destroyed state machine is still reachable through its own API: {sfn_err!r}"
    )
    _assert_roles_gone(ctx.client("iam"), roles)


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _terminal(sfn, execution_arn: str, *, timeout_s: float = 120.0) -> dict:
    """Poll DescribeExecution to any terminal status. Never asserts how long it took."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=execution_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2)
    raise AssertionError(f"{execution_arn} was still RUNNING after {timeout_s}s. Last describe: {last!r}")


def _events(cfn, stack_id: str) -> list[dict]:
    return [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
            for e in page["StackEvents"]]


def _stack_outputs(cfn, stack: str) -> dict[str, str]:
    stacks = cfn.describe_stacks(StackName=stack)["Stacks"]
    assert len(stacks) == 1, f"expected one stack named {stack!r}, got {stacks!r}"
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _stack_physical_ids(cfn, stack: str, resource_type: str) -> list[str]:
    return sorted(r["PhysicalResourceId"]
                  for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                  if r["ResourceType"] == resource_type)


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """GetRole answers NoSuchEntity with its exact message for every role named."""
    for role in roles:
        err = _error(lambda role=role: iam.get_role(RoleName=role))
        assert err == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
            f"GetRole on the removed execution role {role!r} returned {err!r}"
        )


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        time.sleep(2.0)
    raise AssertionError(f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _cdk_env(ctx, qualifier: str, stack: str, *, fix: bool) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.account
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["FIX"] = "1" if fix else "0"
    return env


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    acct = ctx.account
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{acct}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        "--ci", "--no-version-reporting", "--no-notices",
        "--tags", f"sim2real={CHECK}",
    ]
    r = subprocess.run(cmd, cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, *, timeout_s: float,
         expect_rc: int | None, fix: bool) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = _cdk_env(ctx, qualifier, stack, fix=fix)
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices",
           "--app", f"{sys.executable} app.py"]
    if args and args[0] == "deploy":
        cmd += ["--require-approval", "never"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
