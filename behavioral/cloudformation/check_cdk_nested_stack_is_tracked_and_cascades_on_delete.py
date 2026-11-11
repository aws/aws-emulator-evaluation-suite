"""cdk-nested-stack-is-tracked-and-cascades-on-delete."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-nested-stack-is-tracked-and-cascades-on-delete"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_nested_stack"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CDK NestedStack appears under its parent as ParentId/RootId, the parent's output resolves
    through the nested stack's outputs to the nested parameter's name, termination protection on
    it is refused since only a root stack may hold it, and deleting the parent cascades to both.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    parent_stack = ctx.unique_name("sim2real-cdknest-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    marker = ctx.unique_name("marker-")

    work = _stage_app(ctx, _APP)
    bootstrapped = False

    try:
        # Set before bootstrap so a bootstrap that fails partway still has its remnants reaped.
        bootstrapped = True
        _bootstrap(ctx, account, qualifier, toolkit_stack)

        context = {
            "account": account, "region": ctx.region, "stack_name": parent_stack,
            "marker_value": marker, "qualifier": qualifier,
        }
        _cdk(ctx, work, ["deploy", parent_stack, "--require-approval", "never"], context,
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

        parent = cfn.describe_stacks(StackName=parent_stack)["Stacks"][0]
        assert parent["StackStatus"] == "CREATE_COMPLETE", (
            f"parent stack {parent_stack!r} is {parent['StackStatus']!r}, expected CREATE_COMPLETE"
        )
        parent_id = parent["StackId"]

        resources = cfn.describe_stack_resources(StackName=parent_stack)["StackResources"]
        nested = [r for r in resources if r["ResourceType"] == "AWS::CloudFormation::Stack"]
        assert len(nested) == 1, (
            f"parent stack {parent_stack!r} has {len(nested)} AWS::CloudFormation::Stack "
            f"resources, expected exactly 1: {[r['LogicalResourceId'] for r in nested]!r}"
        )
        nested_id = nested[0]["PhysicalResourceId"]
        assert nested_id, (
            f"the nested stack resource {nested[0]['LogicalResourceId']!r} has no "
            f"PhysicalResourceId"
        )

        # 1. the nested stack is visible as a stack of its own, parented to the deploy above it.
        child = cfn.describe_stacks(StackName=nested_id)["Stacks"][0]
        assert child["StackStatus"] == "CREATE_COMPLETE", (
            f"nested stack {nested_id!r} is {child['StackStatus']!r}, expected CREATE_COMPLETE"
        )
        assert child.get("ParentId") == parent_id, (
            f"nested stack {nested_id!r} has ParentId {child.get('ParentId')!r}, expected the "
            f"parent's StackId {parent_id!r}"
        )
        assert child.get("RootId") == parent_id, (
            f"nested stack {nested_id!r} has RootId {child.get('RootId')!r}, expected the "
            f"parent's StackId {parent_id!r} (the parent is itself the root)"
        )

        # 2. the parent's output, resolved through the nested stack's outputs, names the same
        # parameter as the nested stack's own ParamName output.
        parent_outputs = {o["OutputKey"]: o["OutputValue"] for o in parent.get("Outputs", [])}
        child_outputs = {o["OutputKey"]: o["OutputValue"] for o in child.get("Outputs", [])}
        assert parent_outputs.get("ChildParamName") == child_outputs.get("ParamName"), (
            f"parent output ChildParamName={parent_outputs.get('ChildParamName')!r} does not "
            f"match nested stack output ParamName={child_outputs.get('ParamName')!r}"
        )
        param_name = parent_outputs.get("ChildParamName")
        assert param_name, f"parent stack {parent_stack!r} has no ChildParamName output"

        value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
        assert value == marker, (
            f"GetParameter on {param_name!r} (named by the bubbled-up output) returned "
            f"{value!r}, expected the marker {marker!r} the nested resource was created with"
        )

        # 3. NEGATIVE: termination protection is a root-stack-only setting; a nested stack refuses it.
        protect = _client_error(
            lambda: cfn.update_termination_protection(
                StackName=nested_id, EnableTerminationProtection=True)
        )
        assert protect.response["Error"]["Code"] == "ValidationError", (
            f"UpdateTerminationProtection on the nested stack {nested_id!r} returned error code "
            f"{protect.response['Error']['Code']!r}, expected 'ValidationError'"
        )
        assert protect.response["Error"]["Message"] == (
            f"Termination protection cannot be updated due to stack [{nested_id}] being a substack"
        ), protect.response["Error"]["Message"]

        # the refusal left the nested stack and its resource untouched.
        still = cfn.describe_stacks(StackName=nested_id)["Stacks"][0]
        assert still["StackStatus"] == "CREATE_COMPLETE", (
            f"after the refused UpdateTerminationProtection, nested stack {nested_id!r} is "
            f"{still['StackStatus']!r}, expected CREATE_COMPLETE"
        )
        assert still.get("EnableTerminationProtection") is False, (
            f"nested stack {nested_id!r} shows EnableTerminationProtection="
            f"{still.get('EnableTerminationProtection')!r} after a refused request to set it, "
            f"expected False"
        )
        value_after_refusal = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
        assert value_after_refusal == marker, (
            f"after the refused UpdateTerminationProtection, GetParameter on {param_name!r} "
            f"returned {value_after_refusal!r}, expected the unchanged marker {marker!r}"
        )

        # CONTROL: the same request against the PARENT (a root stack) is accepted.
        cfn.update_termination_protection(StackName=parent_stack, EnableTerminationProtection=True)
        protected_parent = cfn.describe_stacks(StackName=parent_stack)["Stacks"][0]
        assert protected_parent.get("EnableTerminationProtection") is True, (
            f"UpdateTerminationProtection(True) on the root stack {parent_stack!r} did not take; "
            f"DescribeStacks shows EnableTerminationProtection="
            f"{protected_parent.get('EnableTerminationProtection')!r}"
        )
        cfn.update_termination_protection(StackName=parent_stack, EnableTerminationProtection=False)

        # 4. deleting the PARENT cascades: the nested stack and its resource both go.
        _delete_stack_and_wait(ctx, parent_stack)

        gone_parent = _client_error(lambda: cfn.describe_stacks(StackName=parent_stack))
        assert gone_parent.response["Error"]["Code"] == "ValidationError", (
            f"DescribeStacks on the deleted parent {parent_stack!r} returned error code "
            f"{gone_parent.response['Error']['Code']!r}, expected 'ValidationError'"
        )
        assert gone_parent.response["Error"]["Message"] == (
            f"Stack with id {parent_stack} does not exist"
        ), gone_parent.response["Error"]["Message"]

        gone_child = cfn.describe_stacks(StackName=nested_id)["Stacks"][0]
        assert gone_child["StackStatus"] == "DELETE_COMPLETE", (
            f"after the parent was deleted, nested stack {nested_id!r} is "
            f"{gone_child['StackStatus']!r}, expected DELETE_COMPLETE"
        )

        gone_param = _client_error(lambda: ssm.get_parameter(Name=param_name))
        assert gone_param.response["Error"]["Code"] == "ParameterNotFound", (
            f"after the parent was deleted, GetParameter on {param_name!r} returned error code "
            f"{gone_param.response['Error']['Code']!r}, expected 'ParameterNotFound' — the "
            f"nested stack's resource must not outlive the cascade"
        )
    finally:
        _teardown(ctx, account, parent_stack, staging_bucket,
                  toolkit_stack if bootstrapped else None, qualifier)


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
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-color"]
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


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 420.0) -> None:
    """Delete, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" in str(exc):
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
        # Bounded: CloudFormation deletes are asynchronous with no notification channel.
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _is_stack_not_found(exc: ClientError, stack: str) -> bool:
    """True only for CloudFormation's own not-found answer for *stack*, in either of its wordings."""
    error = exc.response["Error"]
    return (error["Code"] == "ValidationError"
            and error.get("Message") in (f"Stack with id {stack} does not exist",
                                         f"Stack [{stack}] does not exist"))


def _disable_termination_protection(ctx, stack: str) -> None:
    """Turn termination protection off so the delete is not refused; tolerates only not-found."""
    try:
        ctx.client("cloudformation").update_termination_protection(
            StackName=stack, EnableTerminationProtection=False)
    except ClientError as exc:
        if not _is_stack_not_found(exc, stack):
            raise


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


def _teardown(ctx, account: str, parent_stack: str, staging_bucket: str,
              toolkit_stack: str | None, qualifier: str) -> None:
    """Delete the app stack, then everything bootstrap left, then assert all of it is gone."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    errors: list[str] = []
    steps: list[tuple[str, Any]] = [
        (f"termination protection on {parent_stack}",
         lambda: _disable_termination_protection(ctx, parent_stack)),
        (f"app stack {parent_stack}",
         lambda: _delete_stack_and_wait(
             ctx, parent_stack, timeout_s=max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — collected and raised below, never swallowed
            errors.append(f"{label}: {exc!r}")
    if toolkit_stack and errors:
        # The app stack deletes as the toolkit's exec role: deleting the toolkit now strands it.
        errors.append(f"toolkit stack {toolkit_stack} and staging bucket kept: "
                      f"app stack not deleted")
        toolkit_stack = None
    toolkit_steps: list[tuple[str, Any]] = [] if not toolkit_stack else [
        (f"staging bucket {staging_bucket}",
         lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
        (f"toolkit stack {toolkit_stack}",
         lambda: _delete_stack_and_wait(
             ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic()))),
    ]
    for label, step in toolkit_steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — collected and raised below, never swallowed
            errors.append(f"{label}: {exc!r}")

    if toolkit_stack:
        try:
            remaining = _bootstrap_remnants(ctx, account, staging_bucket, qualifier)
        except Exception as exc:  # noqa: BLE001 — raised with every failure collected so far
            errors.append(f"bootstrap remnant probe: {exc!r}")
            raise AssertionError("teardown left residue: " + "; ".join(errors)) from exc
        else:
            if remaining:
                errors.append(f"bootstrap remnants still present: {remaining!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


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
