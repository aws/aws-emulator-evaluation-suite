"""cdk-bootstrap-custom-permissions-boundary-blocks-a-deploy-outside-it."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-bootstrap-custom-permissions-boundary-blocks-a-deploy-outside-it"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "iam", "sqs"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_QUEUE_APP = "cdk_boundary_queue"
_TABLE_APP = "cdk_boundary_table"

_HANDLER = re.compile(
    r'Resource handler returned message: "(.*?) \(Service: Sqs, '
    r'Status Code: (\d+), Request ID: [0-9a-f-]+\) \(SDK Attempt Count: \d+\)" '
    r'\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (\w+)\)'
)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """`cdk bootstrap --custom-permissions-boundary` puts the named policy on the
    CloudFormationExecutionRole but not the deploy role; a deploy whose action the boundary
    denies is refused naming that ARN, while an allowed action still succeeds.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-customizing.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    boundary_name = ctx.unique_name("sim2real-cdkboundary-")
    queue_name = ctx.unique_name("sim2real-cdkbndq-")
    queue_stack = ctx.unique_name("sim2real-cdkbndqs-")
    table_stack = ctx.unique_name("sim2real-cdkbndts-")
    staging_bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    state: dict[str, Any] = {"policy": False, "bootstrapped": False, "queue_stack": False,
                             "table_stack": False}

    ctx.on_cleanup(lambda: _teardown_all(
        ctx, cfn, iam, state, queue_stack, table_stack, toolkit_stack, staging_bucket,
        boundary_name
    ))

    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowAll", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "DenySqsCreateQueue", "Effect": "Deny", "Action": "sqs:CreateQueue",
             "Resource": "*"},
        ],
    }
    state["policy"] = True
    created_policy = iam.create_policy(
        PolicyName=boundary_name, PolicyDocument=json.dumps(boundary_doc),
        Description="sim2real test boundary: allows everything except sqs:CreateQueue",
    )
    boundary_arn = created_policy["Policy"]["Arn"]

    state["bootstrapped"] = True
    _bootstrap(ctx, qualifier, toolkit_stack, boundary_name)

    exec_role_name = f"cdk-{qualifier}-cfn-exec-role-{ctx.account}-{ctx.region}"
    exec_role = iam.get_role(RoleName=exec_role_name)["Role"]
    boundary = exec_role.get("PermissionsBoundary")
    assert boundary is not None, (
        f"GetRole on {exec_role_name!r} carries no PermissionsBoundary after bootstrapping with "
        f"--custom-permissions-boundary {boundary_name!r}"
    )
    assert boundary["PermissionsBoundaryType"] == "Policy", (
        f"PermissionsBoundaryType was {boundary['PermissionsBoundaryType']!r}, expected 'Policy'"
    )
    assert boundary["PermissionsBoundaryArn"] == boundary_arn, (
        f"{exec_role_name!r} carries boundary {boundary['PermissionsBoundaryArn']!r}, expected "
        f"this run's own policy {boundary_arn!r}"
    )

    # The flag scopes the boundary to the exec role; the deploy role is unaffected by it.
    deploy_role_name = f"cdk-{qualifier}-deploy-role-{ctx.account}-{ctx.region}"
    deploy_role = iam.get_role(RoleName=deploy_role_name)["Role"]
    assert "PermissionsBoundary" not in deploy_role, (
        f"{deploy_role_name!r} unexpectedly carries a PermissionsBoundary "
        f"({deploy_role.get('PermissionsBoundary')!r}); the flag targets the exec role"
    )

    # NEGATIVE: a queue create is explicitly denied by the boundary, so the deploy is refused.
    queue_work = _stage_app(ctx, _QUEUE_APP)
    queue_context = {"account": ctx.account, "region": ctx.region, "stack_name": queue_stack,
                     "qualifier": qualifier, "queue_name": queue_name}
    state["queue_stack"] = True
    rc, output = _cdk(ctx, queue_work, ["deploy", queue_stack, "--require-approval", "never"],
                      queue_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk deploy` of a queue the boundary denies exited {rc}, expected 1 (refused). "
        f"Output tail: {output[-1200:]!r}"
    )
    status = cfn.describe_stacks(StackName=queue_stack)["Stacks"][0]["StackStatus"]
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {queue_stack!r} settled at {status!r}, expected ROLLBACK_COMPLETE"
    )
    events = _events(cfn, queue_stack)
    failed = [e for e in events if e["ResourceType"] == "AWS::SQS::Queue"
             and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one Queue CREATE_FAILED event, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    match = _HANDLER.search(reason)
    assert match is not None, (
        f"CREATE_FAILED reason did not match the handler-message shape: {reason!r}"
    )
    inner_message, http_status, handler_code = match.group(1), match.group(2), match.group(3)
    assert handler_code == "AccessDenied", f"HandlerErrorCode was {handler_code!r}"
    assert http_status == "403", f"the wrapped SQS status code was {http_status!r}"
    queue_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{queue_name}"
    expected_inner = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{exec_role_name}/AWSCloudFormation is "
        f"not authorized to perform: sqs:createqueue on resource: {queue_arn} with an explicit "
        f"deny in a permissions boundary: {boundary_arn}"
    )
    assert inner_message == expected_inner, (
        f"unexpected resource handler message {inner_message!r}, expected {expected_inner!r}"
    )
    resources = cfn.list_stack_resources(StackName=queue_stack)["StackResourceSummaries"]
    left_over = [r for r in resources if r["ResourceStatus"] != "DELETE_COMPLETE"]
    assert left_over == [], (
        f"stack {queue_stack!r} rolled back with non-deleted resource(s) still listed: "
        f"{left_over!r} — a boundary refusal during CREATE must leave nothing provisioned"
    )
    sqs = ctx.client("sqs")
    code, message = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert (code, message) == (
        "AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."
    ), (
        f"GetQueueUrl on {queue_name!r} answered {(code, message)!r} — the boundary-refused "
        f"queue must not exist"
    )

    # CONTROL: a table create is allowed by the same boundary, under the same exec role.
    table_work = _stage_app(ctx, _TABLE_APP)
    table_context = {"account": ctx.account, "region": ctx.region, "stack_name": table_stack,
                     "qualifier": qualifier}
    state["table_stack"] = True
    _cdk(ctx, table_work, ["deploy", table_stack, "--require-approval", "never"], table_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    table_name = _stack_outputs(cfn, table_stack)["TableName"]
    key = ctx.unique_name("key-")
    marker = ctx.unique_name("marker-")
    ddb.put_item(TableName=table_name, Item={"pk": {"S": key}, "marker": {"S": marker}})
    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": key}},
                        ConsistentRead=True).get("Item")
    assert item is not None, (
        f"GetItem on {table_name!r} found nothing at pk={key!r} right after PutItem — "
        f"CREATE_COMPLETE was reached but the deployed table does not work"
    )
    assert item.get("marker", {}).get("S") == marker, (
        f"item at pk={key!r} carries marker {item.get('marker', {}).get('S')!r}, expected "
        f"{marker!r}"
    )


def _bootstrap(ctx, qualifier: str, toolkit_stack: str, boundary_name: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, with the named custom permissions boundary."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboundaryboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--custom-permissions-boundary", boundary_name,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--tags", f"sim2real={CHECK}",
    ]
    result = subprocess.run(cmd, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _events(cfn, stack_name: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        out.extend(page["StackEvents"])
    return list(reversed(out))


def _stack_outputs(cfn, stack_name: str) -> dict[str, str]:
    described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack_name!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float) -> None:
    """Delete by name, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    try:
        cfn.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        if error.get("Code") == "ValidationError" and \
                error.get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "ValidationError" and \
                    error.get("Message") == f"Stack with id {stack_name} does not exist":
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Purge every version and delete marker, then the Retain staging bucket itself."""
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


def _delete_policy(iam, policy_arn: str) -> None:
    try:
        iam.delete_policy(PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _teardown_all(ctx, cfn, iam, state: dict[str, Any], queue_stack: str, table_stack: str,
                  toolkit_stack: str, staging_bucket: str, boundary_name: str) -> None:
    """Delete the app stacks, staging bucket, toolkit stack, then the boundary policy.

    The order matters: the policy cannot be deleted while the exec role still uses it."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps: list[tuple[str, Any]] = []
    if state["queue_stack"]:
        steps.append((f"app stack {queue_stack}", lambda: _delete_stack_and_wait(
            cfn, queue_stack, max(30.0, deadline - time.monotonic()))))
    if state["table_stack"]:
        steps.append((f"app stack {table_stack}", lambda: _delete_stack_and_wait(
            cfn, table_stack, max(30.0, deadline - time.monotonic()))))
    if state["bootstrapped"]:
        steps.append((f"staging bucket {staging_bucket}",
                     lambda: _empty_and_delete_bucket(ctx.client("s3"), staging_bucket)))
        steps.append((f"toolkit stack {toolkit_stack}", lambda: _delete_stack_and_wait(
            cfn, toolkit_stack, max(30.0, deadline - time.monotonic()))))
    if state["policy"]:
        boundary_arn = f"arn:aws:iam::{ctx.account}:policy/{boundary_name}"
        steps.append((f"boundary policy {boundary_arn}",
                      lambda: _delete_policy(iam, boundary_arn)))
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
