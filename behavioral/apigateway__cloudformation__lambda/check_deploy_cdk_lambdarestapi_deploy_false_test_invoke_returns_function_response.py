"""deploy-cdk-lambdarestapi-deploy-false-test-invoke-returns-function-response."""
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

CHECK = "deploy-cdk-lambdarestapi-deploy-false-test-invoke-returns-function-response"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_APP = "cdk_lambdarestapi_deploy_false"
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 180.0
_TEARDOWN_S = 600.0
_POLL_S = 2.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A `LambdaRestApi` built with `deploy=False` creates no Deployment and no Stage, and
    `TestInvokeMethod` still runs the proxy integration and returns the function's own response.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-lrap-")
    fn_name = ctx.unique_name("sim2real-lrap-fn-")
    marker = ctx.unique_name("marker-")
    state: dict[str, Any] = {
        "account": ctx.account, "qualifier": qualifier,
        "toolkit": ctx.unique_name("sim2real-cdktk-"),
        "staging": f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}",
        "stack": stack, "destroyed": False, "log_group": f"/aws/lambda/{fn_name}",
    }
    work = _stage_app(ctx, _APP)
    ctx.on_cleanup(lambda: _teardown(ctx, state))

    context = {"account": ctx.account, "region": ctx.region, "stack_name": stack,
               "function_name": fn_name, "marker": marker,
               "@aws-cdk/core:bootstrapQualifier": qualifier}

    _bootstrap(ctx, state)
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], context,
         timeout_s=_DEPLOY_TIMEOUT_S)

    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}
    for key in ("RestApiId", "FunctionName"):
        assert key in outputs, f"stack outputs {sorted(outputs)!r} lack {key!r}"
    api_id = outputs["RestApiId"]
    assert outputs["FunctionName"] == fn_name, (
        f"FunctionName output {outputs['FunctionName']!r}, expected {fn_name!r}"
    )

    # ---- deploy=False creates no Deployment and no Stage --------------------------------------
    deployments = apigw.get_deployments(restApiId=api_id).get("items", [])
    assert deployments == [], (
        f"RestApi {api_id!r} built with deploy=False has {len(deployments)} deployment(s); "
        f"expected none"
    )
    stages = apigw.get_stages(restApiId=api_id).get("item", [])
    assert stages == [], (
        f"RestApi {api_id!r} built with deploy=False has stages {stages!r}; expected none"
    )

    # ---- TestInvokeMethod still runs the proxy integration and returns the Lambda's response --
    resources = apigw.get_resources(restApiId=api_id)["items"]
    roots = [r for r in resources if r.get("path") == "/"]
    assert len(roots) == 1 and "ANY" in roots[0].get("resourceMethods", {}), (
        f"expected exactly one root resource with an ANY method, got {resources!r}"
    )
    root_id = roots[0]["id"]

    invoked = apigw.test_invoke_method(
        restApiId=api_id, resourceId=root_id, httpMethod="ANY", pathWithQueryString="/",
    )
    assert invoked["status"] == 200, (
        f"TestInvokeMethod on the undeployed API's root ANY method returned status "
        f"{invoked['status']!r}, expected 200: {invoked.get('body')!r}"
    )
    assert json.loads(invoked["body"]) == {"marker": marker}, (
        f"TestInvokeMethod returned body {invoked.get('body')!r}, expected the function's own "
        f"response {{'marker': {marker!r}}}"
    )

    # ---- destroy: the API and the function are both gone, and TestInvokeMethod is unreachable -
    roles = _stack_roles(cfn, stack)
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"
    _cdk(ctx, work, ["destroy", stack, "--force"], context, timeout_s=_DESTROY_TIMEOUT_S)
    state["destroyed"] = True

    gone_stack = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert gone_stack.response["Error"]["Code"] == "ValidationError", gone_stack.response["Error"]
    assert gone_stack.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        gone_stack.response["Error"]["Message"]
    )
    gone_api = _client_error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert gone_api.response["Error"]["Code"] == "NotFoundException", gone_api.response["Error"]
    assert gone_api.response["Error"]["Message"] == (
        f"Invalid API identifier specified {ctx.account}:{api_id}"
    ), gone_api.response["Error"]["Message"]
    gone_fn = _client_error(lambda: lam.get_function(FunctionName=fn_name))
    assert gone_fn.response["Error"]["Code"] == "ResourceNotFoundException", gone_fn.response["Error"]
    assert gone_fn.response["Error"]["Message"] == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    ), gone_fn.response["Error"]["Message"]
    _assert_roles_gone(ctx.client("iam"), roles)


# ===== self-contained helpers =====


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present={(source / 'app.py').is_file()}, "
        f"cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _bootstrap(ctx, state: dict) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-lrap-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{state['account']}/{ctx.region}",
        "--qualifier", state["qualifier"],
        "--toolkit-stack-name", state["toolkit"],
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    _run_cli(ctx, command, scratch, _BOOTSTRAP_TIMEOUT_S,
             f"`cdk bootstrap` for qualifier {state['qualifier']!r}")


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float) -> None:
    """Run the CDK CLI in *work* with the app's context; asserts it exits 0."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    _run_cli(ctx, cmd, work, timeout_s, f"`cdk {' '.join(args[:2])}`")


def _run_cli(ctx, cmd: list[str], cwd: Path, timeout_s: float, what: str) -> None:
    result = subprocess.run(cmd, cwd=cwd, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    assert result.returncode == 0, (
        f"{what} exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )


def _client_error(fn) -> ClientError:
    """The ClientError a call raises."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(_POLL_S)
    raise AssertionError(f"stack {stack!r} not deleted within {timeout_s}s (last {status!r})")


def _reap_log_group(logs, name: str, *, reads: int = 3, budget_s: float = 180.0) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent."""
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
                raise AssertionError(f"log group {name!r} still present after {budget_s}s")
            time.sleep(_POLL_S)


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
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


def _bootstrap_remnants(ctx, state: dict) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    qualifier = state["qualifier"]
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(
            StackName=state["toolkit"])["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {state['toolkit']} in {status}")
    except ClientError as exc:
        if not _stack_missing(exc):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=state["staging"])
        remaining.append(f"staging bucket {state['staging']}")
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


def _teardown(ctx, state: dict) -> None:
    """Delete the app stack (if `cdk destroy` did not already), its function's log group, then
    bootstrap. Every step runs; each failure is collected and the teardown raises naming all."""
    end = time.monotonic() + _TEARDOWN_S

    def left(reserve: float = 0.0) -> float:
        return max(1.0, end - reserve - time.monotonic())

    def check_remnants() -> None:
        remaining = _bootstrap_remnants(ctx, state)
        if remaining:
            raise AssertionError(f"bootstrap remnants still present: {remaining!r}")

    logs = ctx.client("logs")
    steps: list[tuple[str, Any]] = []
    if not state["destroyed"]:
        steps.append((f"stack {state['stack']}",
                      lambda: _delete_stack_and_wait(ctx, state["stack"], timeout_s=left(300.0))))
    steps += [
        (f"log group {state['log_group']}",
         lambda: _reap_log_group(logs, state["log_group"], budget_s=min(180.0, left(180.0)))),
        ("staging bucket", lambda: _empty_and_delete_bucket(ctx, state["staging"])),
        (f"toolkit stack {state['toolkit']}",
         lambda: _delete_stack_and_wait(ctx, state["toolkit"], timeout_s=left())),
        ("bootstrap remnants", check_remnants),
    ]
    errors: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — every step runs; collected, raised below
            errors.append(f"{label}: {exc!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
