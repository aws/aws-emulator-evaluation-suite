"""deploy-cdk-httpapi-lambda-integration-get-routes-and-integrations-read-back."""
from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-httpapi-lambda-integration-get-routes-and-integrations-read-back"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "lambda"]

_APP = "cdk_httpapi_lambda_integration"
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_DESTROY_TIMEOUT_S = 180.0
_SERVE_DEADLINE_S = 90.0
_TEARDOWN_S = 600.0
_POLL_S = 2.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetRoutes/GetIntegrations read back an HttpApi's IAM-authorized `$default` route and AWS_PROXY
    integration, the stage serves the function to a signed GET and refuses an unsigned one, and
    after `cdk destroy` both calls answer the api-gone error.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    agw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-httpint-")
    fn_name = ctx.unique_name("sim2real-httpint-fn-")
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
    for key in ("ApiId", "ApiEndpoint", "FunctionName"):
        assert key in outputs, f"stack outputs {sorted(outputs)!r} lack {key!r}"
    api_id = outputs["ApiId"]
    assert outputs["FunctionName"] == fn_name, (
        f"FunctionName output {outputs['FunctionName']!r}, expected {fn_name!r}"
    )

    # ---- GetRoutes reads back the $default route CDK's defaultIntegration wired --------------
    routes = agw.get_routes(ApiId=api_id)["Items"]
    assert [r["RouteKey"] for r in routes] == ["$default"], (
        f"GetRoutes on {api_id!r} returned {routes!r}, expected exactly one $default route"
    )
    route = routes[0]
    assert route.get("AuthorizationType") == "AWS_IAM", (
        f"the $default route's AuthorizationType is {route.get('AuthorizationType')!r}, expected AWS_IAM"
    )
    target = route.get("Target", "")
    assert target.startswith("integrations/"), (
        f"the $default route's Target is {target!r}, expected an integrations/<id> reference"
    )
    integration_id = target.removeprefix("integrations/")

    # ---- GetIntegrations reads back the one AWS_PROXY integration pointing at the function ---
    integrations = agw.get_integrations(ApiId=api_id)["Items"]
    assert [i["IntegrationId"] for i in integrations] == [integration_id], (
        f"GetIntegrations on {api_id!r} returned {[i['IntegrationId'] for i in integrations]!r}, "
        f"expected exactly the route's own integration {integration_id!r}"
    )
    integration = integrations[0]
    assert integration.get("IntegrationType") == "AWS_PROXY", (
        f"integration {integration_id!r} has IntegrationType {integration.get('IntegrationType')!r}, "
        f"expected AWS_PROXY"
    )
    assert integration.get("PayloadFormatVersion") == "2.0", (
        f"integration {integration_id!r} has PayloadFormatVersion "
        f"{integration.get('PayloadFormatVersion')!r}, expected '2.0'"
    )
    fn_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
    assert integration.get("IntegrationUri") == fn_arn, (
        f"integration {integration_id!r} has IntegrationUri {integration.get('IntegrationUri')!r}, "
        f"expected the deployed function's own ARN {fn_arn!r}"
    )

    # ---- data plane: the $default stage actually serves the function -------------------------
    url = ctx.api_url(api_id, "$default") + "/"
    status, body = _http_until(ctx, url, deadline_s=_SERVE_DEADLINE_S)
    assert status == 200 and json.loads(body) == {"marker": marker}, (
        f"signed GET {url} returned {status} {body!r}, expected 200 {{'marker': {marker!r}}}"
    )
    status, body = _http(ctx, url, sign=False)
    assert (status, json.loads(body)) == (403, {"message": "Forbidden"}), (
        f"unsigned GET {url} returned {status} {body!r}, expected the IAM authorizer's 403"
    )
    roles = _stack_roles(cfn, stack)
    assert len(roles) == 1, f"expected the function's execution role, got {roles!r}"

    # ---- destroy: GetRoutes and GetIntegrations both answer the api-gone error ---------------
    _cdk(ctx, work, ["destroy", stack, "--force"], context, timeout_s=_DESTROY_TIMEOUT_S)
    state["destroyed"] = True

    gone_stack = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert gone_stack.response["Error"]["Code"] == "ValidationError", gone_stack.response["Error"]
    assert gone_stack.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        gone_stack.response["Error"]["Message"]
    )
    expected_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    gone_routes = _client_error(lambda: agw.get_routes(ApiId=api_id))
    assert gone_routes.response["Error"]["Code"] == "NotFoundException", gone_routes.response["Error"]
    assert gone_routes.response["Error"]["Message"] == expected_gone, gone_routes.response["Error"]
    gone_integrations = _client_error(lambda: agw.get_integrations(ApiId=api_id))
    assert gone_integrations.response["Error"]["Code"] == "NotFoundException", (
        gone_integrations.response["Error"]
    )
    assert gone_integrations.response["Error"]["Message"] == expected_gone, (
        gone_integrations.response["Error"]
    )
    gone_fn = _client_error(lambda: lam.get_function(FunctionName=fn_name))
    assert gone_fn.response["Error"]["Code"] == "ResourceNotFoundException", gone_fn.response["Error"]
    assert gone_fn.response["Error"]["Message"] == (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    ), gone_fn.response["Error"]["Message"]
    _assert_roles_gone(ctx.client("iam"), roles)


# ===== self-contained helpers =====


def _stage_app(ctx, name: str) -> Path:
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
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-httpint-boot-"))
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


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, url: str, *, sign: bool = True, timeout_s: float = 20.0) -> tuple[int, bytes]:
    target, headers = ctx.endpoint_route(url)
    if sign:
        headers = _sigv4_headers(ctx, target, headers)
    request = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout_s,
                                    context=_ssl_context(ctx.http_verify)) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _http_until(ctx, url: str, *, deadline_s: float) -> tuple[int, bytes]:
    deadline = time.monotonic() + deadline_s
    status, body = -1, b""
    while time.monotonic() < deadline:
        status, body = _http(ctx, url)
        if status == 200:
            return status, body
        time.sleep(2.0)
    raise AssertionError(
        f"GET {url} never returned 200 within {deadline_s}s; last status {status} body "
        f"{body[:300]!r}"
    )


def _client_error(fn) -> ClientError:
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


def _sigv4_headers(ctx, url: str, headers: dict) -> dict:
    """``headers`` plus SigV4 execute-api headers for a GET of ``url``, with this run's credentials."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    frozen = ctx.client("apigatewayv2")._request_signer._credentials.get_frozen_credentials()
    request = AWSRequest(method="GET", url=url, headers=dict(headers))
    SigV4Auth(frozen, "execute-api", ctx.region).add_auth(request)
    return dict(request.headers.items())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
