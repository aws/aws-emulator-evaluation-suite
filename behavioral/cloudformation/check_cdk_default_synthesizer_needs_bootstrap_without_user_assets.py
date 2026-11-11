"""cdk-default-synthesizer-needs-bootstrap-without-user-assets."""
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

CHECK = "cdk-default-synthesizer-needs-bootstrap-without-user-assets"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_table_bootstrap"
_BOOTSTRAP_ERROR = "Has the environment been bootstrapped?"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An asset-free app deploys unbootstrapped with the bootstrapless synthesizer, but under
    DefaultStackSynthesizer (which makes the template an asset) is refused naming the qualifier's
    SSM parameter, leaving no stack; after `cdk bootstrap` the same deploy works end to end.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    ddb = ctx.client("dynamodb")
    ssm = ctx.client("ssm")

    # A per-run qualifier makes "unbootstrapped" true whatever else the account has bootstrapped.
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    legacy_stack = ctx.unique_name("sim2real-cdkboot-legacy-")
    default_stack = ctx.unique_name("sim2real-cdkboot-default-")
    version_parameter = f"/cdk-bootstrap/{qualifier}/version"
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    base = {"account": account, "region": ctx.region}
    legacy_context = {**base, "stack_name": legacy_stack, "synth": "legacy"}
    default_context = {**base, "stack_name": default_stack, "synth": "default",
                       "qualifier": qualifier}

    work = _stage_app(ctx, _APP)
    state = {"bootstrapped": False}
    ctx.on_cleanup(lambda: _teardown_with_bootstrap(
        ctx, [default_stack, legacy_stack],
        toolkit_stack if state["bootstrapped"] else None,
        staging_bucket, qualifier, version_parameter))

    # Positive control: without it the refusal is indistinguishable from "cannot deploy".
    _cdk(ctx, work, ["deploy", legacy_stack, "--require-approval", "never"], legacy_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    legacy_table = _stack_outputs(ctx, legacy_stack)["TableName"]
    _assert_table_round_trips(ctx, ddb, legacy_table, "legacy-synthesizer arm")

    # The environment really is unbootstrapped for this qualifier at the moment of refusal.
    unbootstrapped = _client_error(lambda: ssm.get_parameter(Name=version_parameter))
    assert unbootstrapped.response["Error"]["Code"] == "ParameterNotFound", (
        f"GetParameter on {version_parameter!r} succeeded, so this qualifier IS bootstrapped and "
        f"the refusal arm below would prove nothing"
    )
    assert unbootstrapped.response["Error"]["Message"] == "", (
        unbootstrapped.response["Error"]["Message"]
    )
    no_bucket = _client_error(lambda: ctx.client("s3").head_bucket(Bucket=staging_bucket))
    assert no_bucket.response["Error"]["Code"] == "404", (
        f"the staging bucket {staging_bucket!r} already exists for qualifier {qualifier!r}, so "
        f"this qualifier is not the clean slate the negative arm needs"
    )
    assert no_bucket.response["Error"]["Message"] == "Not Found", (
        no_bucket.response["Error"]["Message"]
    )

    # Only the synthesizer differs; the output must name this qualifier's parameter.
    rc, output = _cdk(ctx, work, ["deploy", default_stack, "--require-approval", "never"],
                      default_context, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk deploy` exited {rc} with DefaultStackSynthesizer against the unbootstrapped "
        f"qualifier {qualifier!r}. The app declares no user assets, but the default synthesizer "
        f"makes the TEMPLATE an asset, so the publish must be refused with exit 1. Output tail: "
        f"{output[-1000:]!r}"
    )
    assert _BOOTSTRAP_ERROR in output, (
        f"`cdk deploy` failed but not with the bootstrap error. Expected the output to contain "
        f"{_BOOTSTRAP_ERROR!r}; a generic failure cannot be told from a malformed app or absent "
        f"credentials. Output tail: {output[-1200:]!r}"
    )
    assert version_parameter in output, (
        f"the refusal did not name THIS qualifier's parameter {version_parameter!r}, so it does "
        f"not establish that the missing bootstrap for this qualifier was the cause. Output "
        f"tail: {output[-1200:]!r}"
    )

    _assert_stack_absent(ctx, default_stack)
    still_absent = _client_error(lambda: ssm.get_parameter(Name=version_parameter))
    assert still_absent.response["Error"]["Code"] == "ParameterNotFound", (
        f"the refused deploy created {version_parameter!r} — a refusal must leave no trace"
    )
    assert still_absent.response["Error"]["Message"] == "", (
        still_absent.response["Error"]["Message"]
    )

    state["bootstrapped"] = True
    _bootstrap(ctx, account, qualifier, toolkit_stack)
    version = ssm.get_parameter(Name=version_parameter)["Parameter"]["Value"]
    template_version = _bootstrap_template_version(ctx)
    assert version == template_version, (
        f"after `cdk bootstrap`, {version_parameter!r} holds {version!r}, expected "
        f"{template_version!r}, the CdkBootstrapVersion value of the CLI's own bootstrap template"
    )
    _cdk(ctx, work, ["deploy", default_stack, "--require-approval", "never"], default_context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    default_table = _stack_outputs(ctx, default_stack)["TableName"]
    _assert_table_round_trips(ctx, ddb, default_table, "bootstrapped default-synthesizer arm")


def _assert_table_round_trips(ctx, ddb, table_name: str, arm: str) -> None:
    """The deployed table takes a write and gives it back, read with a different operation."""
    key = ctx.unique_name("key-")
    marker = ctx.unique_name("marker-")
    ddb.put_item(TableName=table_name, Item={"pk": {"S": key}, "marker": {"S": marker}})
    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": key}},
                        ConsistentRead=True).get("Item")
    assert item is not None, (
        f"{arm}: GetItem on the deployed table {table_name!r} found nothing at pk={key!r} "
        f"immediately after a PutItem — CREATE_COMPLETE was reached but the table does not work"
    )
    assert item.get("marker", {}).get("S") == marker, (
        f"{arm}: the row at pk={key!r} in {table_name!r} carries marker "
        f"{item.get('marker', {}).get('S')!r}, expected {marker!r}"
    )


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        # An empty key id makes the bootstrap template mint a customer CMK (7-day deletion window).
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci",
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; the "
        f"restore beat cannot run without it. Output tail: "
        f"{(result.stdout + result.stderr)[-1000:]!r}"
    )


def _bootstrap_template_version(ctx) -> str:
    """The SSM version value the installed CLI's bootstrap template declares, read offline."""
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkbootshow-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    result = subprocess.run(["cdk", "bootstrap", "--show-template", "--json", "--ci"], cwd=scratch,
                            env=ctx.subprocess_env(), capture_output=True, text=True,
                            timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap --show-template` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1000:]!r}"
    )
    # The CLI may write a notice line (e.g. an AI-agent banner) before the JSON object.
    template = json.loads(result.stdout[result.stdout.index("{"):])
    return template["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"]


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
                f"teardown left problems behind: {problems!r}; bootstrap remnant read failed: {exc!r}"
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
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`.

    `--no-version-reporting` drops the `AWS::CDK::Metadata` resource and CLI telemetry;
    `--no-color` keeps ANSI escapes out of any asserted output; `--ci` sends logs to stdout.
    """
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
            f"{output[-1200:]!r}"
        )
    return result.returncode, output


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


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


def _assert_stack_absent(ctx, stack: str) -> None:
    """DescribeStacks reports the stack absent with ValidationError and the exact message."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the deleted stack {stack!r} returned error code {code!r}, expected "
        f"'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on the deleted stack {stack!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
