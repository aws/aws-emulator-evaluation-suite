"""deploy-cdk-dynamo-putitem-denied-fails."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-dynamo-putitem-denied-fails"
GROUP = "deploy-cdk"
SERVICES = ["cloudformation", "dynamodb", "stepfunctions"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_DENY_POLICY = "sim2real-deny-putitem"

_APP = "sfn_dynamo_put"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An explicit Deny on the `cdk deploy`-granted state machine role fails the DynamoPutItem task
    with DynamoDB's AccessDeniedException naming the denied write, no item lands, and removing the
    Deny lets the identical execution write it.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-ddb.html
    """
    require_tools("cdk")
    ctx.verify_account_safety()
    acct = ctx.account
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkddbdeny-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    context = {"account": acct, "region": ctx.region, "stack_name": stack, "qualifier": qualifier}
    work = _stage_app(ctx, _APP)

    # Registered before bootstrap and deploy so a part-way failure still tears down; LIFO runs
    # the app stack first, while the toolkit's deploy role still exists.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, staging))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, toolkit))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

    _bootstrap(ctx, qualifier, toolkit)
    _cdk(ctx, work, ["deploy", stack], context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    outputs = _stack_outputs(cfn, stack)
    table_name = outputs["TableName"]
    sm_arn = outputs["StateMachineArn"]
    role_name = outputs["RoleArn"].rsplit("/", 1)[-1]
    roles = _stack_physical_ids(cfn, stack, "AWS::IAM::Role")
    assert roles == [role_name], f"expected the state machine role {role_name!r} only, got {roles!r}"

    def _run(pk: str) -> dict:
        execution = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("exec-"),
            input=json.dumps({"pk": pk, "marker": pk}),
        )
        return _terminal(sfn, execution["executionArn"])

    def _item_present(pk: str) -> bool:
        return "Item" in ddb.get_item(TableName=table_name, Key={"pk": {"S": pk}}, ConsistentRead=True)

    # 1. Positive control: the auto-granted permission lets the task write the item.
    control_pk = ctx.unique_name("ctl-")
    control = _run(control_pk)
    assert control["status"] == "SUCCEEDED", (
        f"positive control ended {control['status']!r}, expected SUCCEEDED "
        f"(error={control.get('error')!r}, cause={control.get('cause')!r})"
    )
    control_item = ddb.get_item(TableName=table_name, Key={"pk": {"S": control_pk}},
                                ConsistentRead=True).get("Item")
    assert control_item == {"pk": {"S": control_pk}, "marker": {"S": control_pk}}, (
        f"positive control item at pk={control_pk!r} is {control_item!r}, expected exactly the "
        f"attributes the task wrote"
    )

    # 2. Break exactly one thing: an explicit Deny on dynamodb:PutItem for this role.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_DENY_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "dynamodb:PutItem", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, _DENY_POLICY))

    # 3. Negative: the identical shape of call, denied. IAM is eventually consistent, so retry on
    #    a transient still-allowed SUCCEEDED with a FRESH key each attempt.
    deadline = time.monotonic() + 90.0
    negative = None
    neg_pk = None
    while True:
        neg_pk = ctx.unique_name("deny-")
        negative = _run(neg_pk)
        if negative["status"] == "FAILED":
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the explicit Deny never took effect within 90s; last status {negative['status']!r}"
            )
        time.sleep(2)
    assert negative["error"] == "DynamoDB.AmazonDynamoDBException", (
        f"expected error DynamoDB.AmazonDynamoDBException once dynamodb:PutItem was denied, got "
        f"error={negative.get('error')!r} cause={negative.get('cause')!r}"
    )
    table_arn = f"arn:aws:dynamodb:{ctx.region}:{acct}:table/{table_name}"
    # The session name and request id are minted per call; every other part is graded exactly.
    want_cause = re.compile(
        re.escape(f"User: arn:aws:sts::{acct}:assumed-role/{role_name}/") + r"[A-Za-z0-9_+=,.@-]+"
        + re.escape(f" is not authorized to perform: dynamodb:PutItem on resource: {table_arn} "
                    "with an explicit deny in an identity-based policy (Service: AmazonDynamoDBv2; "
                    "Status Code: 400; Error Code: AccessDeniedException; Request ID: ")
        + r"[A-Za-z0-9-]+" + re.escape("; Proxy: null)"))
    assert want_cause.fullmatch(negative.get("cause") or ""), (
        f"the denial's cause is {negative.get('cause')!r}, expected DynamoDB's "
        f"AccessDeniedException for {role_name!r} on {table_arn!r} with an explicit deny"
    )

    # 4. Effect absent: the denied write must never have landed.
    assert not _item_present(neg_pk), (
        f"item present at pk={neg_pk!r} despite the execution reporting FAILED"
    )

    # 5. Control: remove the Deny, the identical shape of call succeeds and the item lands.
    _delete_role_policy(iam, role_name, _DENY_POLICY)
    deadline = time.monotonic() + 90.0
    restored = None
    while True:
        restored = _run(neg_pk)
        if restored["status"] == "SUCCEEDED":
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"removing the Deny never restored success within 90s; last status "
                f"{restored['status']!r} (error={restored.get('error')!r})"
            )
        time.sleep(2)
    assert _item_present(neg_pk), "item still missing after the restored, identical call reported SUCCEEDED"

    # `cdk destroy` in-band is the graded teardown path.
    _cdk(ctx, work, ["destroy", stack, "--force"], context, timeout_s=_DEPLOY_TIMEOUT_S,
         expect_rc=0)

    stack_err = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert stack_err == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"DescribeStacks on {stack!r} after `cdk destroy` returned {stack_err!r}"
    )
    ddb_err = _error(lambda: ddb.describe_table(TableName=table_name))
    assert ddb_err == (
        "ResourceNotFoundException", f"Requested resource not found: Table: {table_name} not found"
    ), f"the destroyed table is still reachable through its own API: {ddb_err!r}"
    sfn_err = _error(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert sfn_err == ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{sm_arn}'"), (
        f"the destroyed state machine is still reachable through its own API: {sfn_err!r}"
    )
    role_err = _error(lambda: iam.get_role(RoleName=role_name))
    assert role_err == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the destroyed state machine role {role_name!r} returned {role_err!r}"
    )


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


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _stack_outputs(cfn, stack: str) -> dict[str, str]:
    stacks = cfn.describe_stacks(StackName=stack)["Stacks"]
    assert len(stacks) == 1, f"expected one stack named {stack!r}, got {stacks!r}"
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _stack_physical_ids(cfn, stack: str, resource_type: str) -> list[str]:
    return sorted(r["PhysicalResourceId"]
                  for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                  if r["ResourceType"] == resource_type)


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


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    if args and args[0] == "deploy":
        cmd += ["--require-approval", "never"]
    r = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete or missing"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
