"""cdk-publish-assets-uploads-without-a-stack-then-deploy-skips-the-reupload."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-publish-assets-uploads-without-a-stack-then-deploy-skips-the-reupload"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_CDK_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_asset_gc"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk publish-assets` uploads a stack's file asset to the bootstrap bucket and creates no
    stack (HeadObject succeeds, DescribeStacks does not); a following `cdk deploy` of the same
    asset leaves that object's ETag and LastModified unchanged and creates the stack.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-env.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    # A per-run qualifier makes the staging bucket name and SSM parameter unique to this run.
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkasset-")
    version_parameter = f"/cdk-bootstrap/{qualifier}/version"
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    work = _stage_app(ctx, _APP)
    context = {"account": account, "region": ctx.region, "qualifier": qualifier,
               "stack_name": stack}

    state = {"bootstrapped": False}
    ctx.on_cleanup(lambda: _teardown_with_bootstrap(
        ctx, [stack], toolkit_stack if state["bootstrapped"] else None, staging_bucket,
        qualifier, version_parameter))

    state["bootstrapped"] = True  # set first: a half-finished bootstrap is torn down too
    _bootstrap(ctx, account, qualifier, toolkit_stack)

    _cdk(ctx, work, ["publish-assets", stack], {**context, "code_dir": "lambda_v1"},
         timeout_s=_CDK_TIMEOUT_S, expect_rc=0, unstable="publish-assets")

    bucket, key = _asset_destination(work, stack, "Fn/Code")
    assert bucket == staging_bucket, (
        f"the asset manifest names bucket {bucket!r}, expected this run's staging bucket "
        f"{staging_bucket!r}"
    )
    first_head = s3.head_object(Bucket=bucket, Key=key)
    assert first_head["ContentLength"] > 0, (
        f"HeadObject on the just-published asset {key!r} in {bucket!r} reports a 0-byte object"
    )

    absent = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert absent.response["Error"]["Code"] == "ValidationError", (
        f"publish-assets must create no stack, but DescribeStacks({stack!r}) raised "
        f"{absent.response['Error']['Code']!r} instead of ValidationError"
    )
    assert absent.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        absent.response["Error"]["Message"]
    )

    _cdk(ctx, work, ["deploy", stack], {**context, "code_dir": "lambda_v1"},
         timeout_s=_CDK_TIMEOUT_S, expect_rc=0, extra=["--require-approval", "never"])

    second_head = s3.head_object(Bucket=bucket, Key=key)
    assert second_head["LastModified"] == first_head["LastModified"], (
        f"`cdk deploy` of an already-published asset re-uploaded {key!r}: LastModified moved from "
        f"{first_head['LastModified']!r} to {second_head['LastModified']!r}"
    )
    assert second_head["ETag"] == first_head["ETag"], (
        f"`cdk deploy` of an already-published asset re-uploaded {key!r}: ETag moved from "
        f"{first_head['ETag']!r} to {second_head['ETag']!r}"
    )

    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r} after deploy, expected CREATE_COMPLETE"
    )
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    fn_resource = next(r for r in resources if r["LogicalResourceId"].startswith("Fn"))
    assert fn_resource["ResourceStatus"] == "CREATE_COMPLETE", (
        f"the stack's function resource is {fn_resource['ResourceStatus']!r}, expected "
        f"CREATE_COMPLETE"
    )

    # In-band teardown, asserted: `cdk destroy` deletes the app stack.
    _cdk(ctx, work, ["destroy", stack], {**context, "code_dir": "lambda_v1"},
         timeout_s=_CDK_TIMEOUT_S, expect_rc=0, extra=["--force"])
    _assert_stack_absent(ctx, stack)


def _asset_destination(work: Path, stack: str, display_name: str) -> tuple[str, str]:
    """``(bucket, key)`` of the file asset named ``display_name`` in the staged app's manifest."""
    manifest = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())
    entry = next(f for f in manifest["files"].values() if f["displayName"] == display_name)
    dest = next(iter(entry["destinations"].values()))
    return dest["bucketName"], dest["objectKey"]


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        # AWS_MANAGED_KEY encrypts the staging bucket with the AWS managed S3 key, so the
        # bootstrap template creates no customer managed KMS key.
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci",
        "--no-notices", "--no-version-reporting", "--no-color",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


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


def _teardown_with_bootstrap(ctx, stacks: list[str], toolkit_stack: str | None,
                             staging_bucket: str, qualifier: str, version_parameter: str) -> None:
    """Delete the app stacks, then everything bootstrap left; raise naming whatever remains."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps: list[tuple[str, Any]] = [
        (f"app stack {stack}",
         (lambda s=stack: _delete_stack_and_wait(
             ctx, s, timeout_s=max(30.0, deadline - time.monotonic()))))
        for stack in stacks
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if toolkit_stack and problems:
        # An app stack deletes as the toolkit's exec role: deleting the toolkit now strands it.
        problems.append(f"toolkit stack {toolkit_stack} and staging bucket kept: "
                        f"app stack not deleted")
        toolkit_stack = None
    toolkit_steps: list[tuple[str, Any]] = [] if not toolkit_stack else [
        # The staging bucket has DeletionPolicy: Retain, so it is deleted explicitly.
        (f"staging bucket {staging_bucket}",
         lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
        (f"toolkit stack {toolkit_stack}",
         lambda: _delete_stack_and_wait(
             ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in toolkit_steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if toolkit_stack:
        try:
            remaining = _bootstrap_remnants(ctx, staging_bucket, qualifier, version_parameter)
        except ClientError as exc:
            raise AssertionError(
                f"teardown left problems behind: {problems!r}; bootstrap remnant read "
                f"failed: {exc!r}"
            ) from exc
        else:
            if remaining:
                problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _bootstrap_remnants(ctx, staging_bucket: str, qualifier: str,
                        version_parameter: str) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    try:
        ctx.client("s3").head_bucket(Bucket=staging_bucket)
        remaining.append(f"staging bucket {staging_bucket}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "404":
            raise
    try:
        ctx.client("ssm").get_parameter(Name=version_parameter)
        remaining.append(f"ssm parameter {version_parameter}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
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
         expect_rc: int | None, unstable: str | None = None, extra: list[str] | None = None,
         ) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`.

    `--no-notices` skips the notices fetch; `--no-version-reporting` drops the
    `AWS::CDK::Metadata` resource and CLI telemetry;
    `--no-color` keeps ANSI escapes out of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-notices", "--no-version-reporting", "--no-color"]
    if unstable:
        cmd += ["--unstable", unstable]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    cmd += extra or []
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _assert_stack_absent(ctx, stack: str) -> None:
    """An independent read must report the stack gone with CloudFormation's specific code."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the destroyed stack {stack!r} returned error code {code!r}, expected "
        f"'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on the destroyed stack {stack!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


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
        # Bounded: CloudFormation deletes are asynchronous with no notification channel.
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
