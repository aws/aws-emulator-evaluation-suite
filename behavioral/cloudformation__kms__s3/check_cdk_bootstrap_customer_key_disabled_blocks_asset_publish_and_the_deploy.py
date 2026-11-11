"""cdk-bootstrap-customer-key-disabled-blocks-asset-publish-and-the-deploy."""
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

CHECK = "cdk-bootstrap-customer-key-disabled-blocks-asset-publish-and-the-deploy"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "s3"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_FN_APP = "cdk_customer_key_fn_asset"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Disabling a `--bootstrap-customer-key` CMK blocks publishing to its staging bucket, so a
    later deploy under the same bootstrap never reaches CloudFormation at all, while an earlier
    deploy made under the same still-enabled key already succeeded.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-customizing.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    control_stack = ctx.unique_name("sim2real-cdkckok-")
    broken_stack = ctx.unique_name("sim2real-cdkckbrk-")
    staging_bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    state: dict[str, Any] = {"bootstrapped": False, "control_stack": False, "broken_stack": False}

    ctx.on_cleanup(lambda: _teardown_all(
        ctx, cfn, state, control_stack, broken_stack, toolkit_stack, staging_bucket
    ))

    state["bootstrapped"] = True
    _bootstrap(ctx, qualifier, toolkit_stack)

    key_id = s3.get_bucket_encryption(Bucket=staging_bucket)["ServerSideEncryptionConfiguration"][
        "Rules"][0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"]
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    # CONTROL: the key is enabled, so the first deploy publishes its asset and creates the stack.
    control_work = _stage_app(ctx, _FN_APP)
    control_context = {"account": ctx.account, "region": ctx.region, "stack_name": control_stack,
                       "qualifier": qualifier}
    state["control_stack"] = True
    _cdk(ctx, control_work, ["deploy", control_stack, "--require-approval", "never"],
         control_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    control_status = cfn.describe_stacks(StackName=control_stack)["Stacks"][0]["StackStatus"]
    assert control_status == "CREATE_COMPLETE", (
        f"control stack {control_stack!r} settled at {control_status!r}, expected CREATE_COMPLETE"
    )

    # NEGATIVE: disable the same key, then a second, differently-named stack's asset publish fails.
    kms.disable_key(KeyId=key_arn)
    key_state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert key_state == "Disabled", (
        f"key {key_arn!r} is {key_state!r} right after DisableKey, expected 'Disabled' — the "
        f"negative arm below would prove nothing"
    )

    broken_work = _stage_app(ctx, _FN_APP)
    # A distinct marker makes the Lambda code asset's content hash unique to this stack, so the
    # control deploy above cannot have already published it — the negative arm needs a real
    # upload attempt, not a cache hit on an identically-hashed asset the control already wrote.
    (broken_work / "handler" / "_marker.txt").write_text(broken_stack)
    broken_context = {"account": ctx.account, "region": ctx.region, "stack_name": broken_stack,
                      "qualifier": qualifier}
    broken_manifest = _synth_assets_manifest(ctx, broken_work, broken_context)
    state["broken_stack"] = True
    rc, output = _cdk(ctx, broken_work, ["deploy", broken_stack, "--require-approval", "never"],
                      broken_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk deploy` of {broken_stack!r} with the staging key disabled exited {rc}, expected 1 "
        f"(the asset publish must fail). Output tail: {output[-1200:]!r}"
    )
    expected_fail_line = f"{broken_stack}: fail: {key_arn} is disabled."
    assert expected_fail_line in output, (
        f"`cdk deploy` output did not contain {expected_fail_line!r}, the CLI's own publish-"
        f"failure line naming this run's disabled key. Output tail: {output[-1500:]!r}"
    )

    code, message = _error(lambda: cfn.describe_stacks(StackName=broken_stack))
    assert (code, message) == ("ValidationError", f"Stack with id {broken_stack} does not exist"), (
        f"DescribeStacks on {broken_stack!r} answered {(code, message)!r} — a failed asset "
        f"publish must mean CloudFormation was never even called, so the stack must not exist"
    )
    for file_hash, info in broken_manifest["files"].items():
        dest = next(iter(info["destinations"].values()))
        code, message = _error(
            lambda d=dest: s3.head_object(Bucket=d["bucketName"], Key=d["objectKey"]))
        assert code == "404", (
            f"asset {file_hash!r} ({info.get('displayName')!r}) answered HeadObject with "
            f"{(code, message)!r}, expected 404 — the disabled key must have blocked the upload"
        )


def _bootstrap(ctx, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, with a new customer-managed CMK."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkckdisboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-customer-key",
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


def _synth_assets_manifest(ctx, work: Path, context: dict[str, str]) -> dict:
    """`cdk synth` (no publish) for the asset hashes/keys this app's deploy will try to use."""
    ctx.verify_account_safety()
    cmd = ["cdk", "synth", "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=180)
    assert result.returncode == 0, (
        f"`cdk synth` exited {result.returncode}, expected 0: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
    )
    manifest_path = work / "cdk.out" / f"{context['stack_name']}.assets.json"
    assert manifest_path.is_file(), f"synth did not produce {manifest_path}"
    return json.loads(manifest_path.read_text())


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _teardown_all(ctx, cfn, state: dict[str, Any], control_stack: str, broken_stack: str,
                  toolkit_stack: str, staging_bucket: str) -> None:
    """Delete the app stacks, then the staging bucket, then the toolkit stack.

    Deleting the toolkit stack schedules deletion of its CMK, disabled or not."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps: list[tuple[str, Any]] = []
    if state["control_stack"]:
        steps.append((f"app stack {control_stack}", lambda: _delete_stack_and_wait(
            cfn, control_stack, max(30.0, deadline - time.monotonic()))))
    if state["broken_stack"]:
        steps.append((f"app stack {broken_stack}", lambda: _delete_stack_and_wait(
            cfn, broken_stack, max(30.0, deadline - time.monotonic()))))
    if state["bootstrapped"]:
        steps.append((f"staging bucket {staging_bucket}",
                     lambda: _empty_and_delete_bucket(ctx.client("s3"), staging_bucket)))
        steps.append((f"toolkit stack {toolkit_stack}", lambda: _delete_stack_and_wait(
            cfn, toolkit_stack, max(30.0, deadline - time.monotonic()))))
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
