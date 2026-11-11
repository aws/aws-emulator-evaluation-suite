"""deploy-apigatewayv2-3-cdk-http-api-cors-lambda-default-route-serves-then-destroys."""
from __future__ import annotations

import json
import shutil
import socket
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

CHECK = "deploy-apigatewayv2-3-cdk-http-api-cors-lambda-default-route-serves-then-destroys"
GROUP = "deploy"
SERVICES = ["apigatewayv2"]

_ALLOWED_ORIGIN = "https://example.test"
_DENIED_ORIGIN = "https://evil.example.test"

# Typical durations: synth ~5 s, create ~35 s, delete ~20 s.
_SYNTH_TIMEOUT_S = 180.0
_CREATE_DEADLINE_S = 300.0
_SERVE_DEADLINE_S = 90.0
_DELETE_DEADLINE_S = 240.0
_GONE_DEADLINE_S = 60.0

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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CDK-synthesised HttpApi deploys via CloudFormation, serves its Lambda over the stage
    endpoint, enforces the CORS allowlist on real requests, and stops serving after delete."""
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-apigwv2-cdk3-")
    fn_name = ctx.unique_name("sim2real-apigwv2-cdk3-fn-")
    marker = ctx.unique_name("marker-")
    log_group = f"/aws/lambda/{fn_name}"

    # ---- synthesise (no AWS call; pure CDK) --------------------------------------------------
    template = _synth(ctx, stack, {"stack_name": stack, "function_name": fn_name,
                                   "marker": marker, "allowed_origin": _ALLOWED_ORIGIN})
    resources = template.get("Resources", {})
    by_type: dict[str, list[tuple[str, dict]]] = {}
    for logical_id, res in resources.items():
        by_type.setdefault(res.get("Type"), []).append((logical_id, res))

    stages = by_type.get("AWS::ApiGatewayV2::Stage", [])
    assert len(stages) == 1, (
        f"expected exactly one AWS::ApiGatewayV2::Stage in the synthesised template, got "
        f"{[lid for lid, _ in stages]!r}"
    )
    stage_props = stages[0][1].get("Properties", {})
    assert stage_props.get("StageName") == "$default" and stage_props.get("AutoDeploy") is True, (
        f"the HttpApi's stage must be StageName '$default' with AutoDeploy true, got {stage_props!r}"
    )
    fn_ids = [lid for lid, _ in by_type.get("AWS::Lambda::Function", [])]
    assert len(fn_ids) == 1, f"expected one AWS::Lambda::Function, got {fn_ids!r}"
    fn_props = resources[fn_ids[0]]["Properties"]
    assert "ZipFile" in fn_props.get("Code", {}) and fn_props.get("Runtime") == "python3.12", (
        f"Code.fromInline python3.12 must synthesise an inline ZipFile on python3.12, got "
        f"Code keys {sorted(fn_props.get('Code', {}))!r}, Runtime {fn_props.get('Runtime')!r}"
    )
    perms = by_type.get("AWS::Lambda::Permission", [])
    assert len(perms) == 1, (
        f"HttpLambdaIntegration must synthesise exactly one AWS::Lambda::Permission, got "
        f"{[lid for lid, _ in perms]!r}"
    )
    perm_props = perms[0][1]["Properties"]
    assert (perm_props.get("Principal"), perm_props.get("Action")) == (
        "apigateway.amazonaws.com", "lambda:InvokeFunction"
    ), f"the synthesised Lambda::Permission has unexpected grant {perm_props!r}"
    assert perm_props.get("FunctionName") == {"Fn::GetAtt": [fn_ids[0], "Arn"]}, (
        f"the Lambda::Permission must target the stack's own function {fn_ids[0]!r}, got "
        f"{perm_props.get('FunctionName')!r}"
    )
    apis = by_type.get("AWS::ApiGatewayV2::Api", [])
    assert len(apis) == 1, f"expected one AWS::ApiGatewayV2::Api, got {[l for l, _ in apis]!r}"
    assert apis[0][1]["Properties"].get("CorsConfiguration") == {
        "AllowMethods": ["GET"], "AllowOrigins": [_ALLOWED_ORIGIN]
    }, f"corsPreflight synthesised to {apis[0][1]['Properties'].get('CorsConfiguration')!r}"
    routes = [r["Properties"].get("RouteKey") for _, r in by_type.get("AWS::ApiGatewayV2::Route", [])]
    assert routes == ["$default"], f"defaultIntegration must yield one $default route, got {routes!r}"
    body = json.dumps(template)
    assert "BootstrapVersion" not in template.get("Parameters", {}) and "cdk-bootstrap" not in body, (
        "the template references the CDK bootstrap environment, so it cannot deploy unbootstrapped"
    )

    # ---- deploy via CloudFormation, no bootstrap ---------------------------------------------
    # Nets registered BEFORE the create (LIFO: stack delete runs first, then the log-group reap).
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack, timeout_s=_DELETE_DEADLINE_S))
    destroyed = False
    try:
        cfn.create_stack(StackName=stack, TemplateBody=body, Capabilities=["CAPABILITY_IAM"],
                         Tags=[{"Key": "sim2real", "Value": CHECK[:200]}])
        _wait_stack(cfn, stack, "CREATE_COMPLETE", timeout_s=_CREATE_DEADLINE_S)
        outputs = {o["OutputKey"]: o["OutputValue"]
                   for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
        for key in ("ApiId", "ApiEndpoint", "FunctionName"):
            assert key in outputs, f"stack outputs {sorted(outputs)!r} lack {key!r}"
        api_id, endpoint = outputs["ApiId"], outputs["ApiEndpoint"].rstrip("/")
        assert outputs["FunctionName"] == fn_name, (
            f"FunctionName output {outputs['FunctionName']!r}, expected {fn_name!r}"
        )

        got_api = agw.get_api(ApiId=api_id)
        assert got_api.get("ApiEndpoint", "").rstrip("/") == endpoint, (
            f"GetApi ApiEndpoint {got_api.get('ApiEndpoint')!r} != stack output {endpoint!r}"
        )
        live_stages = {s["StageName"]: s for s in agw.get_stages(ApiId=api_id)["Items"]}
        assert set(live_stages) == {"$default"} and live_stages["$default"].get("AutoDeploy") is True, (
            f"deployed stages {[(n, s.get('AutoDeploy')) for n, s in live_stages.items()]!r}, "
            f"expected only $default with AutoDeploy true"
        )

        # ---- data plane: GET / serves the Lambda's body ---------------------------------------
        url = endpoint + "/"
        status, hdrs, text = _http_until(ctx, url, "GET", {}, want=200, deadline_s=_SERVE_DEADLINE_S)
        served = json.loads(text)
        assert served == {"marker": marker, "path": "/", "method": "GET"}, (
            f"GET / answered {status} {served!r}, expected the Lambda's body with marker {marker!r}"
        )
        status, hdrs, text = _http(ctx, "GET", url, {"Origin": _ALLOWED_ORIGIN})
        assert status == 200 and json.loads(text).get("marker") == marker, (
            f"GET / with an allowed Origin answered {status} {text[:200]!r}"
        )
        assert hdrs.get("access-control-allow-origin") == _ALLOWED_ORIGIN, (
            f"a simple GET from the allowed origin must carry access-control-allow-origin "
            f"{_ALLOWED_ORIGIN!r}, got {hdrs.get('access-control-allow-origin')!r}"
        )

        # ---- preflight from the allowed origin: forwarded through $default, decorated ---------
        # The CDK defaultIntegration creates a $default catch-all route, so API Gateway forwards
        # the preflight to the Lambda (200, not a bare 204) and adds the CORS headers.
        status, hdrs, text = _http(ctx, "OPTIONS", url, {
            "Origin": _ALLOWED_ORIGIN, "Access-Control-Request-Method": "GET"})
        assert status == 200, (
            f"preflight OPTIONS / from the allowed origin answered {status} {text[:200]!r}; real AWS "
            f"forwards it through the $default route to the Lambda and answers 200"
        )
        assert json.loads(text) == {"marker": marker, "path": "/", "method": "OPTIONS"}, (
            f"the preflight body {text[:200]!r} is not the Lambda's OPTIONS answer -- with a "
            f"$default catch-all route the preflight must reach the integration"
        )
        assert hdrs.get("access-control-allow-origin") == _ALLOWED_ORIGIN, (
            f"preflight must carry access-control-allow-origin {_ALLOWED_ORIGIN!r}, got "
            f"{hdrs.get('access-control-allow-origin')!r} (headers {sorted(hdrs)!r})"
        )
        assert hdrs.get("access-control-allow-methods") == "GET", (
            f"preflight access-control-allow-methods must be 'GET', got "
            f"{hdrs.get('access-control-allow-methods')!r}"
        )

        # ---- the allowlist: wrong origin, and right origin with a disallowed method ----------
        for label, headers in (
            ("a non-allowlisted Origin", {"Origin": _DENIED_ORIGIN,
                                          "Access-Control-Request-Method": "GET"}),
            ("the allowed Origin requesting DELETE", {"Origin": _ALLOWED_ORIGIN,
                                                      "Access-Control-Request-Method": "DELETE"}),
        ):
            status, hdrs, text = _http(ctx, "OPTIONS", url, headers)
            assert status == 200, f"preflight from {label} answered {status} {text[:200]!r}"
            assert "access-control-allow-origin" not in hdrs, (
                f"preflight from {label} must NOT get access-control-allow-origin, got "
                f"{hdrs.get('access-control-allow-origin')!r}"
            )
            assert "access-control-allow-methods" not in hdrs, (
                f"preflight from {label} must NOT get access-control-allow-methods, got "
                f"{hdrs.get('access-control-allow-methods')!r}"
            )
        status, hdrs, text = _http(ctx, "GET", url, {"Origin": _DENIED_ORIGIN})
        assert status == 200 and "access-control-allow-origin" not in hdrs, (
            f"GET from a non-allowlisted origin answered {status} with access-control-allow-origin "
            f"{hdrs.get('access-control-allow-origin')!r}; expected 200 and no such header"
        )

        # ---- destroy, then prove the API is gone on both planes -------------------------------
        _delete_stack_and_wait(cfn, stack, timeout_s=_DELETE_DEADLINE_S)
        destroyed = True
        exc = _client_error(lambda: cfn.describe_stacks(StackName=stack))
        assert exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc), (
            f"DescribeStacks on the deleted stack raised {exc.response['Error']!r}"
        )
        code = _client_error(lambda: agw.get_api(ApiId=api_id)).response["Error"]["Code"]
        assert code == "NotFoundException", (
            f"GetApi on {api_id!r} after stack delete raised {code!r}, expected NotFoundException"
        )
        code = _client_error(lambda: lam.get_function(FunctionName=fn_name)).response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"GetFunction on {fn_name!r} after stack delete raised {code!r}, expected "
            f"ResourceNotFoundException"
        )
        gone = _until_gone(ctx, url, deadline_s=_GONE_DEADLINE_S)
        # None: the API's hostname stopped resolving, which is how AWS retires a deleted API.
        if gone is not None:
            status, hdrs, text = gone
            assert json.loads(text) == {"message": "Not Found"}, (
                f"GET / on the deleted API answered {status} {text[:200]!r}, expected 404 "
                f"{{'message': 'Not Found'}}"
            )
            assert marker not in text, f"the deleted endpoint still served the marker: {text[:200]!r}"
    finally:
        # Inline, not only via on_cleanup: a stack delete plus its confirming poll must complete
        # inside the check's own budget rather than racing the registered teardown.
        if not destroyed:
            try:
                _delete_stack_and_wait(cfn, stack, timeout_s=_DELETE_DEADLINE_S)
            except Exception as e:  # noqa: BLE001 — teardown reports, never masks the verdict
                print(f"stack {stack}: {e!r}")


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


def _until_gone(ctx, url, *, deadline_s: float):
    """Poll a deleted API's URL every 2 s until it answers 404 (returned) or its hostname stops
    resolving (None); any other answer at the deadline raises."""
    left = ctx.time_left()
    deadline = time.monotonic() + (deadline_s if left is None else min(deadline_s, left))
    last = None
    while time.monotonic() < deadline:
        try:
            last = _http(ctx, "GET", url, {})
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.gaierror) and e.reason.errno == socket.EAI_NONAME:
                return None
            last = (-1, {}, repr(e))
        except OSError as e:
            last = (-1, {}, repr(e))
        if last[0] == 404:
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"GET {url} neither answered 404 nor stopped resolving within {deadline_s}s; last "
        f"{last[0] if last else None} {(last[2] if last else '')[:200]!r}"
    )


def _reap_log_group(logs, name: str, *, window_s: float = 20.0) -> None:
    """Delete the function's log group in a LOOP: a late log flush can recreate it after delete.
    Registered as a cleanup, so it runs after the stack delete; any leak raises."""
    deadline = time.monotonic() + window_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"log group {name}: {e!r}") from e
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    left = [g["logGroupName"] for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
            if g["logGroupName"] == name]
    if left:
        raise RuntimeError(f"log group {name} reappeared after the reap window")


def _client_error(fn) -> ClientError:
    """The ClientError a call raises."""
    try:
        fn()
    except ClientError as e:
        return e
    raise AssertionError("call succeeded but was expected to be refused")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
