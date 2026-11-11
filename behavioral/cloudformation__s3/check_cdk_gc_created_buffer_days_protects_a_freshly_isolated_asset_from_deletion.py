"""cdk-gc-created-buffer-days-protects-a-freshly-isolated-asset-from-deletion."""
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

CHECK = "cdk-gc-created-buffer-days-protects-a-freshly-isolated-asset-from-deletion"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_CDK_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_ISOLATED_TAG = "aws-cdk:isolated"

_APP = "cdk_asset_gc"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk gc --created-buffer-days 1` must not touch an asset isolated moments ago: too-young
    assets are never scanned for collection, so the object stays present and untagged; the same
    object then falls to `--created-buffer-days 0` in a second pass, proving gc was never inert.

    Reference: https://github.com/aws/aws-cdk-cli/tree/main/packages/aws-cdk#cdk-gc
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkgcbuf-")
    version_parameter = f"/cdk-bootstrap/{qualifier}/version"
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    work = _stage_app(ctx, _APP)
    base_context = {"account": account, "region": ctx.region, "qualifier": qualifier,
                    "stack_name": stack}

    state = {"bootstrapped": False}
    ctx.on_cleanup(lambda: _teardown_with_bootstrap(
        ctx, [stack], toolkit_stack if state["bootstrapped"] else None, staging_bucket,
        qualifier, version_parameter))

    state["bootstrapped"] = True  # set first: a half-finished bootstrap is torn down too
    _bootstrap(ctx, account, qualifier, toolkit_stack)

    _cdk(ctx, work, ["deploy", stack], {**base_context, "code_dir": "lambda_v1"},
         timeout_s=_CDK_TIMEOUT_S, expect_rc=0, extra=["--require-approval", "never"])
    bucket, key_v1 = _asset_destination(work, stack, "Fn/Code")
    assert bucket == staging_bucket, (
        f"the asset manifest names bucket {bucket!r}, expected this run's staging bucket "
        f"{staging_bucket!r}"
    )

    # The redeploy drops key_v1 from the current template: it is isolated from this moment on.
    _cdk(ctx, work, ["deploy", stack], {**base_context, "code_dir": "lambda_v2"},
         timeout_s=_CDK_TIMEOUT_S, expect_rc=0, extra=["--require-approval", "never"])

    before = s3.head_object(Bucket=bucket, Key=key_v1)

    # The negative: created_buffer_days=1 means "ignore anything created less than a day ago",
    # and key_v1 was created moments ago, so a correct gc must leave it alone entirely.
    _gc(ctx, account, toolkit_stack, action="full", rollback_buffer_days=0, created_buffer_days=1)

    after_protected = s3.head_object(Bucket=bucket, Key=key_v1)
    assert after_protected["ETag"] == before["ETag"], (
        f"`cdk gc --created-buffer-days 1` deleted-and-recreated the freshly isolated asset "
        f"{key_v1!r} (ETag moved from {before['ETag']!r} to {after_protected['ETag']!r}); a "
        f"too-young asset must not be touched at all"
    )
    assert after_protected["LastModified"] == before["LastModified"], (
        f"`cdk gc --created-buffer-days 1` modified the freshly isolated asset {key_v1!r} "
        f"(LastModified moved from {before['LastModified']!r} to "
        f"{after_protected['LastModified']!r}); a too-young asset must not be touched at all"
    )
    protected_tags = s3.get_object_tagging(Bucket=bucket, Key=key_v1)["TagSet"]
    assert protected_tags == [], (
        f"`cdk gc --created-buffer-days 1` tagged the freshly isolated asset {key_v1!r} as "
        f"{protected_tags!r}; a too-young asset must not even be tagged"
    )

    # The positive control: the very same object, gc'd with no created-buffer protection, is
    # deletable — proving the prior pass was a real exemption and not an inert or broken `cdk gc`.
    _gc(ctx, account, toolkit_stack, action="full", rollback_buffer_days=0, created_buffer_days=0)
    deleted = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_v1))
    assert deleted.response["Error"]["Code"] == "404", (
        f"with `--created-buffer-days 0`, {key_v1!r} must be collected now that it is no longer "
        f"protected, but HeadObject raised {deleted.response['Error']['Code']!r} instead of 404"
    )

    # In-band teardown, asserted: `cdk destroy` deletes the app stack.
    _cdk(ctx, work, ["destroy", stack], {**base_context, "code_dir": "lambda_v2"},
         timeout_s=_CDK_TIMEOUT_S, expect_rc=0, extra=["--force"])
    _assert_stack_absent(ctx, stack)


def _gc(ctx, account: str, toolkit_stack: str, *, action: str, rollback_buffer_days: int,
        created_buffer_days: int) -> None:
    """`cdk gc` over this run's environment, scoped to its own toolkit stack."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkgc-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "gc", f"aws://{account}/{ctx.region}",
        "--unstable", "gc", "--action", action, "--type", "s3",
        "--toolkit-stack-name", toolkit_stack, "--confirm", "false",
        "--rollback-buffer-days", str(rollback_buffer_days),
        "--created-buffer-days", str(created_buffer_days),
        "--ci", "--no-notices", "--no-version-reporting", "--no-color",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_CDK_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk gc --action {action}` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
    )


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
         expect_rc: int | None, extra: list[str] | None = None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`.

    `--no-notices` skips the notices fetch; `--no-version-reporting` drops the
    `AWS::CDK::Metadata` resource and CLI telemetry;
    `--no-color` keeps ANSI escapes out of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-notices", "--no-version-reporting", "--no-color"]
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
