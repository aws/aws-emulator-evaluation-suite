"""cdk-deploy-lambda-version-alias-invoke-reads-back-configuration."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-lambda-version-alias-invoke-reads-back-configuration"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_lambda_version_alias"
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A plain `cdk deploy` of a Function+Version+Alias: Invoke through the alias runs the
    deployed code and returns its payload, and GetFunction/GetAlias read back what CDK declared.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.account
    lam = ctx.client("lambda")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    staging = f"cdk-{qualifier}-assets-{account}-{ctx.region}"
    stack_name = ctx.unique_name("sim2real-cdkva-")
    marker = ctx.unique_name("marker-")

    work = _stage_app(ctx, _APP)
    fn_names: list[str] = []

    try:
        _bootstrap(ctx, account, qualifier, toolkit)

        base_env = {"CDK_DEFAULT_ACCOUNT": account, "CDK_DEFAULT_REGION": ctx.region,
                    "QUALIFIER": qualifier, "STACK_NAME": stack_name, "MARKER": marker}
        _cdk(ctx, work, ["deploy", stack_name, "--require-approval", "never"], base_env,
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        fn_names = _lambda_function_names(ctx, stack_name)
        role_names = _stack_physical_ids(ctx, stack_name, "AWS::IAM::Role")

        function_name, alias_name, version_number = _stack_outputs(
            ctx, stack_name, "FunctionName", "AliasName", "VersionNumber")

        conf = lam.get_function(FunctionName=function_name)["Configuration"]
        function_arn = conf["FunctionArn"]
        assert conf["Runtime"] == "python3.12", f"deployed Runtime was {conf['Runtime']!r}"
        assert conf["Handler"] == "index.handler", f"deployed Handler was {conf['Handler']!r}"

        alias = lam.get_alias(FunctionName=function_name, Name=alias_name)
        assert alias["FunctionVersion"] == version_number, (
            f"GetAlias reports FunctionVersion {alias['FunctionVersion']!r}, expected the "
            f"CfnOutput-declared version {version_number!r}"
        )
        assert alias["AliasArn"] == f"{function_arn}:{alias_name}", (
            f"GetAlias AliasArn {alias['AliasArn']!r} does not match {function_arn}:{alias_name}"
        )

        payload = {"orderId": ctx.unique_name("order-")}
        resp = lam.invoke(FunctionName=function_name, Qualifier=alias_name,
                          InvocationType="RequestResponse", Payload=json.dumps(payload).encode())
        assert "FunctionError" not in resp, (
            f"invoking through alias {alias_name!r} raised a function error: "
            f"{resp.get('FunctionError')!r}"
        )
        body = json.loads(resp["Payload"].read())
        assert body == {"marker": marker, "echo": payload}, (
            f"invoking through the alias returned {body!r}, expected the handler's payload "
            f"{{'marker': {marker!r}, 'echo': {payload!r}}}"
        )
        assert resp["ExecutedVersion"] == version_number, (
            f"ExecutedVersion was {resp['ExecutedVersion']!r}, expected the alias's pinned "
            f"version {version_number!r}"
        )

        _destroy_stack(ctx, work, stack_name, base_env)

        absent = _error(lambda: lam.get_function(FunctionName=function_name))
        assert absent == ("ResourceNotFoundException", f"Function not found: {function_arn}"), (
            f"GetFunction after `cdk destroy` returned {absent!r}, expected ResourceNotFound "
            f"naming the deleted function's own ARN"
        )
        for qualifier_name in (version_number, alias_name):
            absent = _error(lambda qualifier_name=qualifier_name: lam.get_function(FunctionName=function_name, Qualifier=qualifier_name))
            want = ("ResourceNotFoundException", f"Function not found: {function_arn}:{qualifier_name}")
            assert absent == want, f"GetFunction on {qualifier_name!r} after `cdk destroy` returned {absent!r}"
        iam = ctx.client("iam")
        for role_name in role_names:
            absent = _error(lambda role_name=role_name: iam.get_role(RoleName=role_name))
            assert absent == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
                f"GetRole on the execution role {role_name!r} after `cdk destroy` returned {absent!r}"
            )
    finally:
        _teardown(ctx, stack_name, staging, toolkit, qualifier, account, fn_names)


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError("call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _stack_outputs(ctx, stack_name: str, *keys: str) -> tuple[str, ...]:
    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return tuple(outputs[k] for k in keys)


def _stack_physical_ids(ctx, stack: str, resource_type: str) -> list[str]:
    resources = ctx.client("cloudformation").describe_stack_resources(StackName=stack)["StackResources"]
    found = [r["PhysicalResourceId"] for r in resources if r["ResourceType"] == resource_type]
    assert found, f"stack {stack} declares no {resource_type}: {resources!r}"
    return found


def _lambda_function_names(ctx, stack: str) -> list[str]:
    cfn = ctx.client("cloudformation")
    try:
        resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    except ClientError as exc:
        if _stack_missing(exc):
            return []
        raise
    return [r["PhysicalResourceId"] for r in resources
            if r["ResourceType"] == "AWS::Lambda::Function" and r.get("PhysicalResourceId")]


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir() and (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app this check references is missing or incomplete at {source}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _bootstrap(ctx, account: str, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkva-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0. "
        f"Output tail: {(result.stdout + result.stderr)[-1000:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], extra_env: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env.update(extra_env)
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _destroy_stack(ctx, work: Path, stack_name: str, base_env: dict[str, str]) -> None:
    """The graded in-band `cdk destroy`; raises (never swallows) on a non-zero exit or a timeout."""
    _cdk(ctx, work, ["destroy", stack_name, "--force"], base_env,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(2.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                      for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 2.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} "
                    f"clean reads"
                )
            time.sleep(interval_s)


def _bootstrap_remnants(ctx, staging: str, toolkit: str, qualifier: str, account: str) -> list[str]:
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(StackName=toolkit)["Stacks"][0][
            "StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {toolkit} in {status}")
    except ClientError as exc:
        if not _stack_missing(exc):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=staging)
        remaining.append(f"staging bucket {staging}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append("bootstrap version parameter")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    iam = ctx.client("iam")
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str, account: str,
             fn_names: list[str]) -> None:
    """Delete the app stack (idempotent: the in-band destroy likely already did), its functions'
    log groups, then the bootstrap toolkit and staging bucket. Collects, then raises at the end.
    """
    logs = ctx.client("logs")
    steps: list[tuple[str, object]] = [
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
    ]
    steps += [(f"log group of {fn}", lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
              for fn in fn_names]
    steps += [(f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
              (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit))]
    errors: list[str] = []
    for label, step in steps:
        if label == f"staging bucket {staging}" and any(e.startswith("app stack ") for e in errors):
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket kept: "
                                 + "; ".join(errors))
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown must report, never mask the verdict
            errors.append(f"{label}: {exc!r}")
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining = _bootstrap_remnants(ctx, staging, toolkit, qualifier, account)
    while remaining and time.monotonic() < deadline:
        time.sleep(2.0)
        remaining = _bootstrap_remnants(ctx, staging, toolkit, qualifier, account)
    if remaining:
        errors.append(f"bootstrap remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                      f"{remaining!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
