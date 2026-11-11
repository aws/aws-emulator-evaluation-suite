"""deploy-cdk-dynamo-put-item-task-writes-item-execution-reads-it-back."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-dynamo-put-item-task-writes-item-execution-reads-it-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "stepfunctions"]

_APP = "sfn_dynamo_put"
_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed state machine's DynamoPutItem task ends its execution SUCCEEDED, and a
    GetItem reads back exactly the item the execution's input named, confirming the write
    actually landed rather than only being claimed.
    """
    require_tools("cdk", "node")
    ctx.verify_account_safety()

    account = ctx.account
    sfn = ctx.client("stepfunctions")
    ddb = ctx.client("dynamodb")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack_name = ctx.unique_name("sim2real-cdkdput-")
    context = {
        "account": account,
        "region": ctx.region,
        "stack_name": stack_name,
        "qualifier": qualifier,
    }

    work = _stage_app(ctx, _APP)
    state: dict = {}
    ctx.on_cleanup(lambda: _teardown(ctx, stack_name, toolkit_stack, qualifier, state))

    _bootstrap(ctx, account, qualifier, toolkit_stack)
    _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"], context,
        timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = _stack_outputs(ctx, stack_name)
    machine_arn = outputs["StateMachineArn"]
    table_name = outputs["TableName"]

    described_table = ddb.describe_table(TableName=table_name)["Table"]
    assert described_table["TableStatus"] == "ACTIVE", (
        f"the deployed table {table_name!r} reports TableStatus "
        f"{described_table['TableStatus']!r}, expected ACTIVE"
    )
    described_sm = sfn.describe_state_machine(stateMachineArn=machine_arn)
    assert described_sm["status"] == "ACTIVE", (
        f"the deployed state machine {machine_arn!r} reports status "
        f"{described_sm['status']!r}, expected ACTIVE"
    )

    pk = ctx.unique_name("item-")
    marker = ctx.unique_name("marker-")
    execution_arn = sfn.start_execution(
        stateMachineArn=machine_arn, name=ctx.unique_name("run-"),
        input=json.dumps({"pk": pk, "marker": marker}),
    )["executionArn"]
    terminal = _terminal(ctx, execution_arn)

    assert terminal["status"] == "SUCCEEDED", (
        f"the execution reached {terminal['status']!r}, expected SUCCEEDED "
        f"(error={terminal.get('error')!r}, cause={terminal.get('cause')!r})"
    )

    item = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": pk}}, ConsistentRead=True
    ).get("Item")
    assert item is not None, (
        f"GetItem on {table_name!r} found nothing at pk={pk!r} after a SUCCEEDED execution — "
        f"the DynamoPutItem task reported success but the write never reached the table"
    )
    assert item == {"pk": {"S": pk}, "marker": {"S": marker}}, (
        f"the row at pk={pk!r} in {table_name!r} is {item!r}, expected exactly the pk and marker "
        f"the task's execution input named"
    )

    roles = _stack_roles(ctx.client("cloudformation"), stack_name)
    assert len(roles) == 1, f"expected 1 execution role(s) in the stack, got {roles!r}"
    _destroy(ctx, work, stack_name, context)
    _assert_state_machine_absent(ctx, machine_arn)
    _assert_table_absent(ctx, ddb, table_name)
    _assert_roles_gone(ctx.client("iam"), roles)


def _terminal(ctx, execution_arn: str, *, timeout_s: float = 120.0) -> dict:
    """Poll DescribeExecution to any terminal status. Never asserts how long it took."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=execution_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2)
    raise AssertionError(
        f"{execution_arn} was still RUNNING after {timeout_s}s. Last describe: {last!r}"
    )


def _assert_state_machine_absent(ctx, machine_arn: str) -> None:
    """DescribeStateMachine reports the deleted machine absent with its exact error."""
    sfn = ctx.client("stepfunctions")
    exc = _client_error(lambda: sfn.describe_state_machine(stateMachineArn=machine_arn))
    code = exc.response["Error"]["Code"]
    assert code == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on the destroyed machine {machine_arn!r} returned error code "
        f"{code!r}, expected 'StateMachineDoesNotExist'"
    )
    assert exc.response["Error"]["Message"] == f"State Machine Does Not Exist: '{machine_arn}'", (
        f"DescribeStateMachine on the destroyed machine raised with message "
        f"{exc.response['Error']['Message']!r}"
    )


def _assert_table_absent(ctx, ddb, table_name: str) -> None:
    """DescribeTable reports the deleted table absent with its exact error."""
    exc = _client_error(lambda: ddb.describe_table(TableName=table_name))
    code = exc.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", (
        f"DescribeTable on the destroyed table {table_name!r} returned error code "
        f"{code!r}, expected 'ResourceNotFoundException'"
    )
    assert exc.response["Error"]["Message"] == "Requested resource not found: Table: "\
        f"{table_name} not found", (
        f"DescribeTable on the destroyed table raised with message "
        f"{exc.response['Error']['Message']!r}"
    )


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-notices",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0. "
        f"Output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*. `--ci --no-notices` only silence telemetry and notice prompts
    and never affect the synthesized template; `deploy` also needs `--require-approval never`
    because a non-interactive run has no terminal to confirm an IAM-sensitive change set."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-notices"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}. Output "
            f"tail: {output[-1500:]!r}"
        )
    return result.returncode, output


def _destroy(ctx, work: Path, stack_name: str, context: dict[str, str]) -> None:
    """The graded `cdk destroy`, run in-band; `ctx.on_cleanup`'s teardown is only the safety net."""
    _cdk(ctx, work, ["destroy", stack_name, "--force"], context, timeout_s=_DEPLOY_TIMEOUT_S,
        expect_rc=0)


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket. Only this run's staging bucket."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(2.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _bootstrap_remnants(ctx, staging_bucket: str, qualifier: str) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "404":
            raise
    iam = ctx.client("iam")
    roles = [
        role["RoleName"]
        for page in iam.get_paginator("list_roles").paginate()
        for role in page["Roles"]
        if role["RoleName"].startswith(f"cdk-{qualifier}-")
    ]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(ctx, stack_name: str, toolkit_stack: str, qualifier: str, state: dict) -> None:
    """Delete the app stack (if `cdk destroy` did not already), then the toolkit stack and its
    staging bucket; raise naming whatever remains."""
    account = ctx.account
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    try:
        _delete_stack_and_wait(ctx, stack_name, timeout_s=max(30.0, deadline - time.monotonic()))
    except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
        problems.append(f"app stack {stack_name}: {exc!r}")
        problems.append(f"toolkit stack {toolkit_stack} and staging bucket kept: "
                        f"app stack not deleted")
        raise AssertionError(f"teardown left problems behind: {problems!r}")

    for label, step in [
        (f"staging bucket {staging_bucket}", lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
        (f"toolkit stack {toolkit_stack}",
         lambda: _delete_stack_and_wait(
             ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic()))),
    ]:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")

    try:
        remaining = _bootstrap_remnants(ctx, staging_bucket, qualifier)
    except ClientError as exc:
        raise AssertionError(
            f"teardown left problems behind: {problems!r}; bootstrap remnant read failed: {exc!r}"
        ) from exc
    if remaining:
        problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
