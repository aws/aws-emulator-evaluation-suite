"""deploy-apigatewayv2-3-cdk-http-api-stripped-lambda-permission-invoke-rejected."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-apigatewayv2-3-cdk-http-api-stripped-lambda-permission-invoke-rejected"
GROUP = "deploy"
SERVICES = ["apigatewayv2"]

_ALLOWED_ORIGIN = "https://example.test"

# Typical durations: synth ~5 s, create ~35 s, update ~10 s, delete ~20 s.
_SYNTH_TIMEOUT_S = 180.0
_CREATE_DEADLINE_S = 300.0
_SERVE_DEADLINE_S = 90.0
_DELETE_DEADLINE_S = 240.0

_APP_PY = '''
import aws_cdk as cdk
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration

app = cdk.App()
stack_name = app.node.try_get_context("stack_name")
fn_name = app.node.try_get_context("function_name")
marker = app.node.try_get_context("marker")
allowed_origin = app.node.try_get_context("allowed_origin")

# LegacyStackSynthesizer: no BootstrapVersion parameter, no /cdk-bootstrap/ rule, no asset
# manifest -- the template deploys through plain CloudFormation in an unbootstrapped account.
stack = cdk.Stack(app, stack_name, stack_name=stack_name,
                  synthesizer=cdk.LegacyStackSynthesizer())

code = (
    "import json\\n"
    "def handler(event, context):\\n"
    "    return {'statusCode': 200, 'headers': {'content-type': 'application/json'},\\n"
    "            'body': json.dumps({'marker': '" + marker + "', 'path': event.get('rawPath'),\\n"
    "                                'method': event['requestContext']['http']['method']})}\\n"
)
# An explicit, stack-owned log group so the function's logs are deleted with the stack.
log_group = logs.LogGroup(stack, "FnLogs", log_group_name=f"/aws/lambda/{fn_name}",
                          removal_policy=cdk.RemovalPolicy.DESTROY,
                          retention=logs.RetentionDays.ONE_DAY)
fn = _lambda.Function(stack, "Fn", function_name=fn_name, runtime=_lambda.Runtime.PYTHON_3_12,
                      handler="index.handler", code=_lambda.Code.from_inline(code),
                      log_group=log_group)
api = apigwv2.HttpApi(
    stack, "Api", api_name=stack_name,
    cors_preflight=apigwv2.CorsPreflightOptions(allow_origins=[allowed_origin],
                                                allow_methods=[apigwv2.CorsHttpMethod.GET]),
    default_integration=HttpLambdaIntegration("Integ", fn),
)
cdk.CfnOutput(stack, "ApiId", value=api.api_id)
cdk.CfnOutput(stack, "ApiEndpoint", value=api.api_endpoint)
cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)
app.synth()
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With the synthesised Lambda::Permission stripped, the deployed HttpApi's $default route
    answers 500 and never reaches the function; restoring only that resource restores service."""
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-apigwv2-cdk3n-")
    fn_name = ctx.unique_name("sim2real-apigwv2-cdk3n-fn-")
    marker = ctx.unique_name("marker-")
    log_group = f"/aws/lambda/{fn_name}"

    full = _synth(ctx, stack, {"stack_name": stack, "function_name": fn_name,
                               "marker": marker, "allowed_origin": _ALLOWED_ORIGIN})
    perm_ids = [lid for lid, r in full["Resources"].items() if r.get("Type") == "AWS::Lambda::Permission"]
    assert len(perm_ids) == 1, (
        f"HttpLambdaIntegration must synthesise exactly one AWS::Lambda::Permission, got {perm_ids!r}"
    )
    stripped = copy.deepcopy(full)
    del stripped["Resources"][perm_ids[0]]
    assert perm_ids[0] not in json.dumps(stripped), (
        f"something else in the template references {perm_ids[0]!r}; stripping it would not be "
        f"the single defect this check needs"
    )

    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack, timeout_s=_DELETE_DEADLINE_S))
    try:
        cfn.create_stack(StackName=stack, TemplateBody=json.dumps(stripped),
                         Capabilities=["CAPABILITY_IAM"],
                         Tags=[{"Key": "sim2real", "Value": CHECK[:200]}])
        _wait_stack(cfn, stack, "CREATE_COMPLETE", timeout_s=_CREATE_DEADLINE_S)
        outputs = {o["OutputKey"]: o["OutputValue"]
                   for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
        api_id, endpoint = outputs["ApiId"], outputs["ApiEndpoint"].rstrip("/")
        url = endpoint + "/"

        # The control plane sees a complete, healthy API.
        routes = [r["RouteKey"] for r in agw.get_routes(ApiId=api_id)["Items"]]
        assert routes == ["$default"], f"deployed routes {routes!r}, expected ['$default']"
        integ = agw.get_integrations(ApiId=api_id)["Items"]
        assert len(integ) == 1 and integ[0]["IntegrationType"] == "AWS_PROXY", (
            f"deployed integrations {[(i.get('IntegrationType'), i.get('IntegrationUri')) for i in integ]!r}"
        )

        # ---- the one defect: no resource policy lets API Gateway invoke the function ---------
        code = _client_error(lambda: lam.get_policy(FunctionName=fn_name)).response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"GetPolicy on the stripped function raised {code!r}, expected ResourceNotFoundException "
            f"(no resource policy at all)"
        )

        status, hdrs, text = _http_until(ctx, url, "GET", {}, want=500, deadline_s=_SERVE_DEADLINE_S)
        for attempt in range(3):
            if attempt:
                status, hdrs, text = _http(ctx, "GET", url, {})
            assert status == 500, (
                f"GET / with no invoke permission answered {status} {text[:200]!r} on attempt "
                f"{attempt + 1}, expected 500"
            )
            assert json.loads(text) == {"message": "Internal Server Error"}, (
                f"GET / with no invoke permission answered body {text[:200]!r}, expected "
                f"{{'message': 'Internal Server Error'}}"
            )
            assert marker not in text, (
                f"the function's marker leaked into the refused response: {text[:200]!r}"
            )

        # ---- positive control: the function itself is healthy --------------------------------
        resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(
            {"rawPath": "/", "requestContext": {"http": {"method": "GET"}}}).encode())
        payload = resp["Payload"].read()
        assert "FunctionError" not in resp, f"direct invoke raised {resp.get('FunctionError')!r}: {payload[:300]!r}"
        direct = json.loads(json.loads(payload)["body"])
        assert direct == {"marker": marker, "path": "/", "method": "GET"}, (
            f"direct invoke returned {direct!r}; the function must be healthy so the 500 is the "
            f"missing permission alone"
        )

        # ---- repair exactly the one thing, on the same stack ---------------------------------
        cfn.update_stack(StackName=stack, TemplateBody=json.dumps(full),
                         Capabilities=["CAPABILITY_IAM"],
                         Tags=[{"Key": "sim2real", "Value": CHECK[:200]}])
        _wait_stack(cfn, stack, "UPDATE_COMPLETE", timeout_s=_CREATE_DEADLINE_S)
        policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
        stmts = policy.get("Statement", [])
        assert len(stmts) == 1, f"restored resource policy has {len(stmts)} statements: {stmts!r}"
        stmt = stmts[0]
        assert stmt.get("Principal") == {"Service": "apigateway.amazonaws.com"}, (
            f"restored statement principal {stmt.get('Principal')!r}"
        )
        source_arn = stmt.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn", "")
        assert source_arn.endswith(f":{api_id}/*/*"), (
            f"restored statement SourceArn {source_arn!r} is not scoped to API {api_id!r}/*/*"
        )

        status, hdrs, text = _http_until(ctx, url, "GET", {}, want=200, deadline_s=_SERVE_DEADLINE_S)
        assert json.loads(text) == {"marker": marker, "path": "/", "method": "GET"}, (
            f"after restoring the permission GET / answered {status} {text[:200]!r}, expected the "
            f"Lambda's body with marker {marker!r}"
        )
    finally:
        try:
            _delete_stack_and_wait(cfn, stack, timeout_s=_DELETE_DEADLINE_S)
        except Exception as e:  # noqa: BLE001 — teardown reports, never masks the verdict
            print(f"stack {stack}: {e!r}")


# ===== helpers =====


def _synth(ctx, stack: str, context: dict[str, str]) -> dict:
    """Write the asset-free CDK app to a temp dir, `cdk synth` it, return the stack template."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-apigwv2-cdk3-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "app.py").write_text(_APP_PY)
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    cmd = ["cdk", "synth", "--ci", "--no-version-reporting", "--no-path-metadata",
           "--no-asset-metadata", "--no-color", "-o", "cdk.out"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION"] = "1"
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                       timeout=_SYNTH_TIMEOUT_S)
    assert r.returncode == 0, f"`cdk synth` exited {r.returncode}: {(r.stdout + r.stderr)[-1200:]!r}"
    path = work / "cdk.out" / f"{stack}.template.json"
    assert path.is_file(), f"cdk synth wrote no {path.name}; cdk.out has {sorted(p.name for p in path.parent.iterdir())!r}"
    return json.loads(path.read_text())


def _http(ctx, method: str, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    """One raw, unsigned HTTPS request (the dp:endpoint leg). Headers are lower-cased."""
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers), **_route})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def _http_until(ctx, url, method, headers, *, want: int, deadline_s: float):
    """Poll until the endpoint answers `want` (a stage serves seconds after CREATE_COMPLETE)."""
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = _http(ctx, method, url, headers)
        except (urllib.error.URLError, OSError) as e:
            last = (-1, {}, repr(e))
        if last[0] == want:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"{method} {url} never answered {want} within {deadline_s}s; last {last[0] if last else None} "
        f"{(last[2] if last else '')[:200]!r}"
    )


def _wait_stack(cfn, stack: str, want: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status == want:
            return
        if status.endswith("_FAILED") or "ROLLBACK" in status:
            reasons = [
                f"{e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}"
                for e in cfn.describe_stack_events(StackName=stack)["StackEvents"]
                if e.get("ResourceStatus", "").endswith("FAILED")
            ][:5]
            raise AssertionError(f"stack {stack!r} reached {status!r}; failures {reasons!r}")
        time.sleep(5.0)
    raise AssertionError(f"stack {stack!r} not {want} within {timeout_s}s (last {status!r})")


def _delete_stack_and_wait(cfn, stack: str, *, timeout_s: float) -> None:
    """Delete and poll to gone; DELETE_FAILED is a failure, never an accepted terminal state."""
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as e:
        if "does not exist" in str(e):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if "does not exist" in str(e):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED")
        time.sleep(5.0)
    raise AssertionError(f"stack {stack!r} not deleted within {timeout_s}s (last {status!r})")


def _reap_log_group(logs, name: str, *, window_s: float = 20.0) -> None:
    """Delete the function's log group in a LOOP: a late log flush can recreate it after delete.
    Any delete error other than not-found, or a group that reappears, raises."""
    deadline = time.monotonic() + window_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"log group {name}: {e!r}") from e
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    left = [g["logGroupName"] for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
            if g["logGroupName"] == name]
    if left:
        raise RuntimeError(f"log group {name} reappeared after the reap window")


def _client_error(fn) -> ClientError:
    """The ClientError a call raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as e:
        return e
    raise AssertionError("call succeeded but was expected to be refused")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
