"""cdk-bootstrap-version-gate-blocks-deploy-until-rebootstrapped."""
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

CHECK = "cdk-bootstrap-version-gate-blocks-deploy-until-rebootstrapped"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "ssm"]

_APP = "cdk_table_bootstrap"
_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 900.0


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A toolkit stack downgraded below the app's `requiresBootstrapStackVersion` makes `cdk deploy`
    refuse, naming both versions, with no stack created; after `cdk bootstrap` restores the
    version, the same deploy succeeds and `cdk destroy` removes the stack.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    ddb = ctx.client("dynamodb")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack_name = ctx.unique_name("sim2real-cdkver-")
    version_parameter = f"/cdk-bootstrap/{qualifier}/version"
    staging_bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    context = {
        "account": ctx.account, "region": ctx.region, "stack_name": stack_name,
        "synth": "default", "qualifier": qualifier,
    }

    work = _stage_app(ctx, _APP)

    # The installed CLI's own template and the app's own requirement, both read offline (no AWS
    # call), so the downgrade target below is derived, never guessed.
    current_template = _show_template(ctx)
    current_version = int(
        current_template["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"]
    )
    required = _synth_required_version(ctx, work, stack_name, context, version_parameter)
    assert current_version > required, (
        f"the installed CLI's own bootstrap template carries version {current_version}, which "
        f"does not exceed the app's required version {required} -- there is no room below it to "
        f"downgrade into for this check's negative arm"
    )
    stale_version = required - 1

    state = {"bootstrapped": False}
    ctx.on_cleanup(lambda: _teardown(ctx, cfn, ctx.client("s3"), stack_name, toolkit_stack,
                                     staging_bucket, state))

    state["bootstrapped"] = True
    _bootstrap(ctx, qualifier, toolkit_stack)
    real_version = int(ssm.get_parameter(Name=version_parameter)["Parameter"]["Value"])
    assert real_version == current_version, (
        f"freshly bootstrapped {version_parameter!r} holds {real_version!r}, expected the "
        f"installed CLI's own template version {current_version!r}"
    )

    # Downgrade the SAME toolkit stack with a genuinely older template -- the stand-in for an
    # account whose bootstrap predates this app's requirement. CloudFormation, not a bare SSM
    # overwrite, is what moves the parameter, so the drop is the real mechanism, not a fiction.
    stale_template = _with_bootstrap_version(current_template, stale_version)
    _bootstrap(ctx, qualifier, toolkit_stack, template=stale_template, force=True)
    downgraded = int(ssm.get_parameter(Name=version_parameter)["Parameter"]["Value"])
    assert downgraded == stale_version, (
        f"after the forced downgrade, {version_parameter!r} holds {downgraded!r}, expected "
        f"{stale_version!r}"
    )

    env_name = f"aws://{ctx.account}/{ctx.region}"
    expected_message = (
        f"{stack_name}: This CDK deployment requires bootstrap stack version "
        f"'{required}', found '{stale_version}' in {env_name}. Please run 'cdk bootstrap'."
    )
    rc, output = _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"], context,
                      timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk deploy` exited {rc} against bootstrap version {stale_version} with the app "
        f"requiring {required}; expected exit 1 with no stack ever created. Output tail: "
        f"{output[-1200:]!r}"
    )
    assert expected_message in output, (
        f"`cdk deploy` output did not contain the documented bootstrap-version-gate message "
        f"{expected_message!r}. Output tail: {output[-1500:]!r}"
    )

    _assert_stack_absent(ctx, stack_name)
    still_stale = int(ssm.get_parameter(Name=version_parameter)["Parameter"]["Value"])
    assert still_stale == stale_version, (
        f"the refused deploy left {version_parameter!r} at {still_stale!r}, expected it "
        f"unchanged at {stale_version!r} -- a client-side refusal must leave no trace"
    )

    # Restore: re-running `cdk bootstrap` with the CLI's own (newer) template is a genuine change
    # from the stale one currently deployed, so CloudFormation updates the parameter back up.
    _bootstrap(ctx, qualifier, toolkit_stack)
    restored = int(ssm.get_parameter(Name=version_parameter)["Parameter"]["Value"])
    assert restored == current_version, (
        f"after re-running `cdk bootstrap`, {version_parameter!r} holds {restored!r}, expected "
        f"it restored to {current_version!r}"
    )

    # Positive control: the identical deploy that was refused a moment ago now succeeds end to end.
    _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"], context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    table_name = _stack_output(cfn, stack_name, "TableName")
    _assert_table_round_trips(ctx, ddb, table_name)

    # The in-band destroy is the graded teardown; the registered cleanup is only the safety net.
    _cdk(ctx, work, ["destroy", stack_name, "--force"], context,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    _assert_stack_absent(ctx, stack_name)


def _assert_table_round_trips(ctx, ddb, table_name: str) -> None:
    """The deployed table takes a write and gives it back, read with a different operation."""
    key = ctx.unique_name("key-")
    marker = ctx.unique_name("marker-")
    ddb.put_item(TableName=table_name, Item={"pk": {"S": key}, "marker": {"S": marker}})
    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": key}},
                        ConsistentRead=True).get("Item")
    assert item is not None, (
        f"GetItem on the deployed table {table_name!r} found nothing at pk={key!r} immediately "
        f"after PutItem -- CREATE_COMPLETE was reached but the table does not work"
    )
    assert item.get("marker", {}).get("S") == marker, (
        f"the row at pk={key!r} in {table_name!r} carries marker "
        f"{item.get('marker', {}).get('S')!r}, expected {marker!r}"
    )


def _show_template(ctx) -> dict[str, Any]:
    """The installed CDK CLI's own current bootstrap template, read offline."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkbootshow-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = ["cdk", "bootstrap", "--show-template", "--json", "--ci", "--no-version-reporting",
          "--no-notices", "--no-color"]
    result = subprocess.run(cmd, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=180)
    assert result.returncode == 0, (
        f"`cdk bootstrap --show-template` exited {result.returncode}, expected 0: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
    )
    # The CLI may write a notice line (e.g. an AI-agent banner) before the JSON object.
    return json.loads(result.stdout[result.stdout.index("{"):])


def _with_bootstrap_version(template: dict[str, Any], version: int) -> dict[str, Any]:
    """A copy of *template* with the `CdkBootstrapVersion` resource's `Value` set to *version*."""
    stale = json.loads(json.dumps(template))
    stale["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"] = str(version)
    return stale


def _synth_required_version(ctx, work: Path, stack_name: str, context: dict[str, str],
                            expected_param: str) -> int:
    """`cdk synth`'s manifest `requiresBootstrapStackVersion` for this stack, read offline."""
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
    manifest = json.loads((work / "cdk.out" / "manifest.json").read_text())
    properties = manifest["artifacts"][stack_name]["properties"]
    ssm_param = properties["bootstrapStackVersionSsmParameter"]
    assert ssm_param == expected_param, (
        f"synthesized stack {stack_name!r} reads its bootstrap version from {ssm_param!r}, "
        f"expected {expected_param!r} for this run's qualifier"
    )
    return int(properties["requiresBootstrapStackVersion"])


def _bootstrap(ctx, qualifier: str, toolkit_stack: str, *, template: dict[str, Any] | None = None,
              force: bool = False) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        # AWS_MANAGED_KEY encrypts the staging bucket with `aws/s3`, so bootstrap creates no CMK.
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--tags", f"sim2real={CHECK}",
    ]
    if template is not None:
        template_path = scratch / "bootstrap-template.json"
        template_path.write_text(json.dumps(template))
        command += ["--template", str(template_path)]
    if force:
        command += ["--force"]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} (custom template={template is not None}, "
        f"force={force}) exited {result.returncode}, expected 0. Output tail: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
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


def _stack_output(cfn, stack_name: str, key: str) -> str:
    """One Output of a CREATE_COMPLETE stack, read from CloudFormation."""
    described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack_name!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}
    assert key in outputs, (
        f"stack {stack_name!r} outputs {sorted(outputs)!r} do not include {key!r}"
    )
    return outputs[key]


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _assert_stack_absent(ctx, stack_name: str) -> None:
    """DescribeStacks reports the stack absent with ValidationError and the exact message."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack_name))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the never-created stack {stack_name!r} returned error code {code!r}, "
        f"expected 'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack_name} does not exist", (
        f"DescribeStacks on {stack_name!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack_name} does not exist":
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
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED during teardown")
        # Bounded: CloudFormation deletes are asynchronous with no notification channel.
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket.

    The bootstrap StagingBucket has `DeletionPolicy: Retain`, so the toolkit delete leaves it.
    """
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


def _teardown(ctx, cfn, s3, stack_name: str, toolkit_stack: str, staging_bucket: str,
             state: dict[str, bool]) -> None:
    """Delete the app stack, then everything bootstrap left; raise naming whatever remains."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps: list[tuple[str, Any]] = [
        (f"app stack {stack_name}",
         lambda: _delete_stack_and_wait(cfn, stack_name, max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if not state["bootstrapped"]:
        if problems:
            raise AssertionError(f"teardown left problems behind: {problems!r}")
        return
    if problems:
        # An app stack deletes as the toolkit's exec role: deleting the toolkit now strands it.
        problems.append(f"toolkit stack {toolkit_stack} and staging bucket {staging_bucket} "
                        f"kept: app stack not deleted")
        toolkit_steps: list[tuple[str, Any]] = []
    else:
        toolkit_steps = [
            (f"staging bucket {staging_bucket}",
             lambda: _empty_and_delete_bucket(s3, staging_bucket)),
            (f"toolkit stack {toolkit_stack}",
             lambda: _delete_stack_and_wait(
                 cfn, toolkit_stack, max(30.0, deadline - time.monotonic()))),
        ]
    for label, step in toolkit_steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
