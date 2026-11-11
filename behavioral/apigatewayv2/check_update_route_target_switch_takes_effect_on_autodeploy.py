"""update-route-target-switch-takes-effect-on-autodeploy."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-route-target-switch-takes-effect-on-autodeploy"
GROUP = 'stage-deploy'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

_EVENT_ECHO_CODE = """
import json
def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(event),
    }
"""


def _http(method, url, body=None, headers=None):
    """HTTP request via urllib; returns (status, headers_dict, body_str)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _poll_http(url, want, method="GET", headers=None, body=None, timeout_s=120):
    """Poll a URL until status == want (absorbing DNS/auto-deploy settling)."""
    status, resp_headers, resp_body = None, {}, ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, resp_headers, resp_body = _http(method, url, body=body, headers=headers or {})
        except Exception:  # noqa: BLE001 - DNS/connect warm-up, retried within the budget
            time.sleep(3)
            continue
        if status == want:
            break
        time.sleep(3)
    return status, resp_headers, resp_body


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=TAGS_KV,
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return arn


def _delete_lambda_log_group(ctx, function_name):
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_lambda(ctx, handler_code):
    """Create a python Lambda; return {name, arn}. Registers teardown."""
    role_arn = _create_lambda_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 10,
        "MemorySize": 128,
        "Tags": dict(TAGS),
    }
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, name))
    deadline = time.monotonic() + 60
    arn = None
    while arn is None:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
        except ClientError as e:
            # IAM propagation: a freshly created role is not yet assumable by Lambda.
            if "cannot be assumed" in str(e) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"lambda {name} did not become Active within 60s (last {state!r})")
        time.sleep(2.0)
    return {"name": name, "arn": arn}


def _allow_apigw_invoke(ctx, fn_name, api_id):
    ctx.client("lambda").add_permission(
        FunctionName=fn_name,
        StatementId="apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/*",
    )


def _create_http_api(ctx, **extra):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS, **extra
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"], api["ApiEndpoint"]


def _url(ctx, api_endpoint, stage, path):
    return f"{ctx.stage_url(api_endpoint, stage)}/{path.lstrip('/')}"


def _poll_version(url, want, timeout_s=120):
    """Poll GET url until the echoed event's ``version`` is ``want``; return (status, event)."""
    status, ev = None, None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status, _, body = _http("GET", url)
        except Exception:  # noqa: BLE001 - DNS/connect warm-up, retried within the budget
            time.sleep(3)
            continue
        if status == 200:
            ev = json.loads(body)
            if ev.get("version") == want:
                break
        time.sleep(3)
    return status, ev


def _deployments(agw, api_id):
    items, token = [], None
    while True:
        kw = {"ApiId": api_id, "NextToken": token} if token else {"ApiId": api_id}
        page = agw.get_deployments(**kw)
        items.extend(page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateRoute re-pointing a Target on an auto-deploy stage re-routes live traffic and moves the
    stage to a new AutoDeployed deployment; integrations differ only in PayloadFormatVersion.
    """
    agw = ctx.client("apigatewayv2")
    fn = _create_lambda(ctx, _EVENT_ECHO_CODE)
    api_id, api_endpoint = _create_http_api(ctx)
    integ = {}
    for label, pfv in (("A", "1.0"), ("B", "2.0")):
        integ[label] = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=fn["arn"],
            IntegrationMethod="POST",
            PayloadFormatVersion=pfv,
        )["IntegrationId"]
    route_id = agw.create_route(
        ApiId=api_id, RouteKey="GET /who", Target=f"integrations/{integ['A']}"
    )["RouteId"]
    _allow_apigw_invoke(ctx, fn["name"], api_id)
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True, Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="$default"))

    url = _url(ctx, api_endpoint, "$default", "/who")
    status, ev = _poll_version(url, "1.0")
    assert status == 200 and ev is not None and ev.get("version") == "1.0", (
        f"before UpdateRoute GET /who must be served by integration A (version 1.0); "
        f"got {status}: {ev!r}"
    )

    # The deployment serving A. AutoDeploy publishes asynchronously, so read it once A serves.
    before_dep = agw.get_stage(ApiId=api_id, StageName="$default").get("DeploymentId")
    assert before_dep, "the auto-deploy stage reports no DeploymentId while it serves traffic"

    agw.update_route(ApiId=api_id, RouteId=route_id, Target=f"integrations/{integ['B']}")
    got = agw.get_route(ApiId=api_id, RouteId=route_id)
    assert got.get("Target") == f"integrations/{integ['B']}", (
        f"GetRoute must report the new Target, got {got.get('Target')!r}"
    )
    assert got.get("RouteKey") == "GET /who", f"UpdateRoute changed RouteKey: {got.get('RouteKey')!r}"

    status, ev = _poll_version(url, "2.0")
    assert status == 200 and ev is not None and ev.get("version") == "2.0", (
        f"after UpdateRoute GET /who must converge on integration B (version 2.0); "
        f"got {status}: {ev!r}"
    )
    assert ev.get("routeKey") == "GET /who", f"routeKey after the switch was {ev.get('routeKey')!r}"

    deadline = time.monotonic() + 60
    while True:
        after_dep = agw.get_stage(ApiId=api_id, StageName="$default").get("DeploymentId")
        if after_dep and after_dep != before_dep:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                "the auto-deploy stage's DeploymentId did not move to a new deployment within 60s "
                "of UpdateRoute"
            )
        time.sleep(2.0)
    listed = {d["DeploymentId"]: d for d in _deployments(agw, api_id)}
    assert before_dep in listed and after_dep in listed, (
        f"GetDeployments must list both the earlier and the current deployment; "
        f"listed {len(listed)} deployment(s), earlier present={before_dep in listed}, "
        f"current present={after_dep in listed}"
    )
    cur = listed[after_dep]
    assert cur.get("AutoDeployed") is True, (
        f"the deployment UpdateRoute produced must be AutoDeployed=true, got {cur.get('AutoDeployed')!r}"
    )
    assert cur.get("DeploymentStatus") == "DEPLOYED", (
        f"the current deployment's status expected DEPLOYED, got {cur.get('DeploymentStatus')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
