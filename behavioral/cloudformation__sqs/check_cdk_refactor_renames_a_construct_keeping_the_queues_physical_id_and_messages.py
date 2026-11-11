"""cdk-refactor-renames-a-construct-keeping-the-queues-physical-id-and-messages."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-refactor-renames-a-construct-keeping-the-queues-physical-id-and-messages"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_REFACTOR_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_refactor_queue_rename"
_OLD_ID = "Queue"
_NEW_ID = "QueueRenamed"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """`cdk refactor` renaming a deployed construct keeps the SQS queue's physical id and its
    CloudFormation resource status, so a message already in the queue survives the rename.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/refactor.html
    Reference: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cmd-refactor.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdkrf-")
    app_stack = ctx.unique_name("sim2real-cdkrf-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    marker = ctx.unique_name("marker-")

    work = _stage_app(ctx, _APP)
    # Registered before bootstrap so a half-created toolkit is torn down too. Cleanups run LIFO,
    # so this runs after the app-stack cleanup below.
    ctx.on_cleanup(lambda: _teardown_bootstrap(ctx, account, app_stack, staging_bucket,
                                               toolkit_stack, qualifier))
    _bootstrap(ctx, account, qualifier, toolkit_stack)

    def context(construct_id: str) -> dict[str, str]:
        return {
            "stack_name": app_stack, "construct_id": construct_id,
            "@aws-cdk/core:bootstrapQualifier": qualifier,
        }

    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, app_stack, timeout_s=_TEARDOWN_DEADLINE_S))
    _cdk(ctx, work, ["deploy", app_stack, "--require-approval", "never"], context(_OLD_ID),
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    before = _single_resource(cfn, app_stack)
    assert before["ResourceType"] == "AWS::SQS::Queue", (
        f"the deployed stack's only resource is {before['ResourceType']!r}, expected "
        f"AWS::SQS::Queue"
    )
    assert before["LogicalResourceId"].startswith(_OLD_ID), (
        f"the deployed queue's logical id is {before['LogicalResourceId']!r}, expected it to "
        f"start with {_OLD_ID!r}"
    )
    before_url = before["PhysicalResourceId"]

    sqs.send_message(QueueUrl=before_url, MessageBody=marker)
    # SendMessage before a rename is only a meaningful control if it is actually receivable
    # on the queue the stack just created.
    seeded = sqs.receive_message(QueueUrl=before_url, MaxNumberOfMessages=1,
                                 WaitTimeSeconds=10).get("Messages", [])
    assert seeded and seeded[0]["Body"] == marker, (
        f"the marker message was not receivable from the freshly deployed queue "
        f"{before_url!r} before the refactor; ReceiveMessage returned {seeded!r}"
    )
    receipt = seeded[0]["ReceiptHandle"]
    # Returned rather than deleted, so it is still IN the queue for the post-refactor read.
    sqs.change_message_visibility(QueueUrl=before_url, ReceiptHandle=receipt,
                                  VisibilityTimeout=0)

    # ---- cdk refactor: rename the construct, keep the queue ---------------------------------
    rc, out = _cdk(
        ctx, work,
        ["refactor", "--unstable=refactor", "-y", "--toolkit-stack-name", toolkit_stack],
        context(_NEW_ID), timeout_s=_REFACTOR_TIMEOUT_S, expect_rc=None,
    )
    assert rc == 0, f"`cdk refactor` exited {rc}, expected 0; output tail: {out[-1500:]!r}"
    assert f"{app_stack}/{_OLD_ID}/Resource" in out and f"{app_stack}/{_NEW_ID}/Resource" in out, (
        f"`cdk refactor` did not name both the old and new construct paths in its output; "
        f"output tail: {out[-1500:]!r}"
    )

    # ---- TERMINAL READ: same physical queue, new logical id, status never left CREATE --------
    after = _single_resource(cfn, app_stack)
    assert after["LogicalResourceId"].startswith(_NEW_ID), (
        f"after `cdk refactor`, the queue's logical id is {after['LogicalResourceId']!r}, "
        f"expected it to start with {_NEW_ID!r}"
    )
    assert after["PhysicalResourceId"] == before_url, (
        f"the queue's physical id changed from {before_url!r} to "
        f"{after['PhysicalResourceId']!r} — `cdk refactor` replaced the resource instead of "
        f"renaming it"
    )
    assert after["ResourceStatus"] == "CREATE_COMPLETE", (
        f"after `cdk refactor`, the queue's ResourceStatus is {after['ResourceStatus']!r}, "
        f"expected CREATE_COMPLETE — a true rename never goes through an UPDATE or a "
        f"replacement's DELETE+CREATE"
    )

    survivors = sqs.receive_message(QueueUrl=before_url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=10).get("Messages", [])
    assert survivors and survivors[0]["Body"] == marker, (
        f"after the rename, ReceiveMessage on {before_url!r} returned {survivors!r}, "
        f"expected the marker {marker!r} seeded before the refactor — a replaced queue "
        f"would have come back empty"
    )

    # ---- the renamed construct destroys cleanly under its new logical id -------------------
    _cdk(ctx, work, ["destroy", app_stack, "--force"], context(_NEW_ID),
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    _assert_stack_absent(cfn, app_stack)


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci",
        "--no-version-reporting", "--no-notices", "--no-color",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1000:]!r}"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
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


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`.

    `--no-version-reporting` drops the `AWS::CDK::Metadata` resource and CLI telemetry;
    `--no-color` keeps ANSI escapes out of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-version-reporting",
           "--no-notices", "--no-color"]
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


def _single_resource(cfn, stack: str) -> dict:
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    assert len(resources) == 1, (
        f"stack {stack!r} has {len(resources)} resources, expected exactly 1: "
        f"{[r['LogicalResourceId'] for r in resources]!r}"
    )
    return resources[0]


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _is_stack_not_found(exc, stack):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _is_stack_not_found(exc: ClientError, stack: str) -> bool:
    error = exc.response["Error"]
    return (error["Code"] == "ValidationError"
            and error.get("Message") in (f"Stack with id {stack} does not exist",
                                         f"Stack [{stack}] does not exist"))


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


def _teardown_bootstrap(ctx, account: str, app_stack: str, staging_bucket: str,
                        toolkit_stack: str, qualifier: str) -> None:
    """Delete what bootstrap created, then assert none of it remains; keep it if the app stack
    still exists, because that stack deletes as the toolkit's execution role."""
    try:
        ctx.client("cloudformation").describe_stacks(StackName=app_stack)
    except ClientError as exc:
        if not _is_stack_not_found(exc, app_stack):
            raise
    else:
        raise AssertionError(f"toolkit stack {toolkit_stack} and staging bucket {staging_bucket} "
                             f"kept: app stack {app_stack} was not deleted")
    _empty_and_delete_bucket(ctx, staging_bucket)
    _delete_stack_and_wait(ctx, toolkit_stack, timeout_s=_TEARDOWN_DEADLINE_S)
    remaining = _bootstrap_remnants(ctx, account, staging_bucket, qualifier)
    assert not remaining, f"bootstrap remnants still present: {remaining!r}"


def _assert_stack_absent(cfn, stack: str) -> None:
    """DescribeStacks by name must report the destroyed stack gone."""
    try:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        error = exc.response["Error"]
        assert _is_stack_not_found(exc, stack), (
            f"DescribeStacks on the destroyed stack {stack!r} raised {error['Code']!r}: "
            f"{error.get('Message')!r}, expected the stack-does-not-exist ValidationError"
        )
        return
    raise AssertionError(f"stack {stack!r} still reports {status!r} after `cdk destroy`")


def _bootstrap_remnants(ctx, account: str, staging_bucket: str, qualifier: str) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append(f"ssm parameter /cdk-bootstrap/{qualifier}/version")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    repository = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[repository])
        remaining.append(f"ecr repository {repository}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
