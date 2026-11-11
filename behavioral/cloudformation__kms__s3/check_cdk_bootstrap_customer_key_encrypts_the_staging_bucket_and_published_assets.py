"""cdk-bootstrap-customer-key-encrypts-the-staging-bucket-and-published-assets."""
from __future__ import annotations

import glob
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

CHECK = "cdk-bootstrap-customer-key-encrypts-the-staging-bucket-and-published-assets"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "s3"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_FN_APP = "cdk_customer_key_fn_asset"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk bootstrap --bootstrap-customer-key` makes the staging bucket SSE-KMS with a new
    customer-managed CMK (S3 GetBucketEncryption, KMS DescribeKey), and every object the CLI
    later publishes there is itself encrypted with that same key (S3 HeadObject).

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-customizing.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    fn_stack = ctx.unique_name("sim2real-cdkckfn-")
    staging_bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    state: dict[str, Any] = {"bootstrapped": False, "fn_stack": False}

    ctx.on_cleanup(lambda: _teardown_all(
        ctx, cfn, state, fn_stack, toolkit_stack, staging_bucket
    ))

    state["bootstrapped"] = True
    _bootstrap(ctx, qualifier, toolkit_stack)

    encryption = s3.get_bucket_encryption(Bucket=staging_bucket)
    rules = encryption["ServerSideEncryptionConfiguration"]["Rules"]
    assert len(rules) == 1, (
        f"staging bucket {staging_bucket!r} has {len(rules)} SSE rules, expected 1"
    )
    default = rules[0]["ApplyServerSideEncryptionByDefault"]
    assert default["SSEAlgorithm"] == "aws:kms", (
        f"staging bucket {staging_bucket!r} default SSE algorithm is "
        f"{default['SSEAlgorithm']!r}, expected 'aws:kms' under --bootstrap-customer-key"
    )
    key_id = default.get("KMSMasterKeyID")
    assert key_id, f"staging bucket {staging_bucket!r} SSE-KMS rule names no KMS key id"

    key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert key_meta["KeyManager"] == "CUSTOMER", (
        f"key {key_id!r} backing the staging bucket has KeyManager "
        f"{key_meta['KeyManager']!r}, expected 'CUSTOMER' — not the bootstrap's own CMK"
    )
    assert key_meta["KeyState"] == "Enabled", (
        f"key {key_id!r} is {key_meta['KeyState']!r} right after bootstrap, expected 'Enabled'"
    )
    key_arn = key_meta["Arn"]

    work = _stage_app(ctx, _FN_APP)
    context = {"account": ctx.account, "region": ctx.region, "stack_name": fn_stack,
              "qualifier": qualifier}
    state["fn_stack"] = True
    _cdk(ctx, work, ["deploy", fn_stack, "--require-approval", "never"], context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    manifest_path = _assets_manifest(work, fn_stack)
    manifest = json.loads(manifest_path.read_text())
    assert manifest["files"], f"{manifest_path} declares no published files"

    checked = 0
    for file_hash, info in manifest["files"].items():
        destinations = list(info["destinations"].values())
        assert len(destinations) == 1, (
            f"asset {file_hash!r} ({info.get('displayName')!r}) has "
            f"{len(destinations)} destinations, expected 1"
        )
        dest = destinations[0]
        assert dest["bucketName"] == staging_bucket, (
            f"asset {file_hash!r} published to {dest['bucketName']!r}, expected this run's "
            f"staging bucket {staging_bucket!r}"
        )
        head = s3.head_object(Bucket=staging_bucket, Key=dest["objectKey"])
        assert head.get("ServerSideEncryption") == "aws:kms", (
            f"published object {dest['objectKey']!r} ({info.get('displayName')!r}) has "
            f"ServerSideEncryption {head.get('ServerSideEncryption')!r}, expected 'aws:kms'"
        )
        assert head.get("SSEKMSKeyId") == key_arn, (
            f"published object {dest['objectKey']!r} ({info.get('displayName')!r}) is "
            f"encrypted with key {head.get('SSEKMSKeyId')!r}, expected this bucket's own key "
            f"{key_arn!r}"
        )
        checked += 1
    assert checked == 2, (
        f"checked {checked} published object(s), expected 2 (the Lambda asset zip and the "
        f"stack template): {sorted(manifest['files'])!r}"
    )


def _bootstrap(ctx, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, with a new customer-managed CMK."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkckboot-"))
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


def _assets_manifest(work: Path, stack_name: str) -> Path:
    """The `cdk.out/<stack>.assets.json` the deploy just produced."""
    candidates = glob.glob(str(work / "cdk.out" / f"{stack_name}.assets.json"))
    assert len(candidates) == 1, (
        f"expected exactly one assets manifest for {stack_name!r} under {work}/cdk.out, found "
        f"{candidates!r}"
    )
    return Path(candidates[0])


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


def _teardown_all(ctx, cfn, state: dict[str, Any], fn_stack: str, toolkit_stack: str,
                  staging_bucket: str) -> None:
    """Delete the app stack, then the staging bucket, then the toolkit stack.

    The toolkit stack's own CMK has `DeletionPolicy: Delete`, so deleting the toolkit stack
    schedules the key's own deletion; no separate KMS call is made here.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps: list[tuple[str, Any]] = []
    if state["fn_stack"]:
        steps.append((f"app stack {fn_stack}", lambda: _delete_stack_and_wait(
            cfn, fn_stack, max(30.0, deadline - time.monotonic()))))
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
