"""xsvc-apigateway-2-sfn-start-sync-execution-maps-output-and-failed-shape."""
from __future__ import annotations

import json
import random
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-2-sfn-start-sync-execution-maps-output-and-failed-shape"
GROUP = "data-format"
SERVICES = ["apigateway", "stepfunctions"]

_DEFINITION = {
    "StartAt": "Route",
    "States": {
        "Route": {"Type": "Choice",
                  "Choices": [{"Variable": "$.body.reject", "IsPresent": True, "Next": "Reject"}],
                  "Default": "Price"},
        "Price": {"Type": "Pass", "End": True, "Parameters": {
            "orderId.$": "$.body.orderId",
            "total.$": "States.MathAdd($.body.a, $.body.b)",
            "gatewayRequestId.$": "$.gatewayRequestId"}},
        "Reject": {"Type": "Fail", "Error": "OrderRejected",
                   "CausePath": "States.Format('order {} rejected: {}', $.body.orderId, $.body.reject)"},
    },
}

# The execution input is the client body plus the gateway's own $context.requestId.
_REQUEST_TEMPLATE = (
    '{"stateMachineArn": "__SM__", '
    '"input": "{\\"body\\": $util.escapeJavaScript($input.json(\'$\')), '
    '\\"gatewayRequestId\\": \\"$context.requestId\\"}"}'
)
# SUCCEEDED and FAILED are both HTTP 200 from StartSyncExecution; the template branches on the
# execution status and inlines the output document (a JSON string) as JSON.
_RESPONSE_TEMPLATE = (
    '{"status": "$input.path(\'$.status\')", '
    '"executionArn": "$input.path(\'$.executionArn\')", '
    '#if($input.path(\'$.status\') == "SUCCEEDED")"output": $input.path(\'$.output\')'
    '#else"error": "$input.path(\'$.error\')", '
    '"cause": "$util.escapeJavaScript($input.path(\'$.cause\'))"#end}'
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A StartSyncExecution integration returns a SUCCEEDED run's output and a FAILED run's error and cause,
    both as HTTP 200, and DescribeExecution refuses the express executionArn with InvalidArn."""
    sm_arn = _create_state_machine(ctx, _DEFINITION, "EXPRESS")
    role = _create_role(ctx, "apigateway.amazonaws.com",
                        inline_policy=_allow(["states:StartSyncExecution"], sm_arn))
    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw2-sfnsync")
    rid = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="price")["id"]
    ag.put_method(restApiId=api_id, resourceId=rid, httpMethod="POST", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=rid, httpMethod="POST", type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:states:action/StartSyncExecution",
        credentials=role["arn"], passthroughBehavior="NEVER",
        requestTemplates={"application/json": _REQUEST_TEMPLATE.replace("__SM__", sm_arn)},
    )
    ag.put_method_response(restApiId=api_id, resourceId=rid, httpMethod="POST", statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=rid, httpMethod="POST",
                                statusCode="200",
                                responseTemplates={"application/json": _RESPONSE_TEMPLATE})
    _deploy_stage(ctx, api_id, "live")
    url = _rest_invoke_url(ctx, api_id, "live", "/price")
    hdrs = {"Content-Type": "application/json"}

    rng = random.Random()
    a, b = rng.randint(1000, 9999), rng.randint(1000, 9999)
    order = ctx.unique_name("ord-")
    _, h, t = _poll_http(url, accept=lambda s, t: s == 200 and '"status"' in t,
                         body=json.dumps({"orderId": order, "a": a, "b": b}).encode(),
                         headers=hdrs, description="StartSyncExecution through the integration")
    ok = json.loads(t)
    assert ok["status"] == "SUCCEEDED", f"sync execution did not succeed: {ok!r}"
    assert ok["output"] == {"orderId": order, "total": a + b,
                            "gatewayRequestId": h.get("x-amzn-requestid")}, (
        f"workflow output mapped back was {ok['output']!r}; expected orderId {order!r}, "
        f"total {a + b} and gatewayRequestId {h.get('x-amzn-requestid')!r}")
    assert ":express:" in ok["executionArn"] and sm_arn.split(":stateMachine:")[1] in ok["executionArn"], (
        f"executionArn {ok['executionArn']!r} is not an express execution of {sm_arn!r}")

    st, _, t = _http("POST", url, body=json.dumps(
        {"orderId": order, "a": a, "b": b, "reject": "out-of-stock"}).encode(), headers=hdrs)
    assert st == 200, f"a FAILED sync execution must still be HTTP 200, got {st}: {t[:300]!r}"
    bad = json.loads(t)
    assert bad == {"status": "FAILED", "executionArn": bad.get("executionArn"),
                   "error": "OrderRejected",
                   "cause": f"order {order} rejected: out-of-stock"}, (
        f"FAILED execution was mapped as {bad!r}; expected error OrderRejected and the "
        f"States.Format cause")
    assert bad["executionArn"] != ok["executionArn"], "two requests reported one execution"

    sfn = ctx.client("stepfunctions")
    code, message = _error(lambda: sfn.describe_execution(executionArn=ok["executionArn"]))
    assert code == "InvalidArn", (
        f"DescribeExecution of an EXPRESS execution must be refused with InvalidArn, got {code!r}")
    assert message == "Invalid Arn: 'Resource type not valid in this context: express'", (
        f"DescribeExecution of an EXPRESS execution said {message!r}")



_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-"), "sim2real": CHECK}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) fn() raised; raises if fn() succeeds, so an accepted call is
    never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"call was expected to be rejected but SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return it. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=30):
    """HTTP via urllib. Returns (status, lower-cased headers, text); 4xx/5xx are RESULTS."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return (e.code, {k.lower(): v for k, v in e.headers.items()},
                e.read().decode("utf-8", "replace"))


def _poll_http(url, *, accept, method="POST", body=None, headers=None, timeout_s=240.0,
               interval_s=4.0, description="invoke URL"):
    """Poll an invoke URL until accept(status, text); return (status, headers, text).

    Stage/execute-api DNS propagation and the integration role's IAM propagation are real
    and expose no condition but the request itself, so the first request through a freshly
    deployed stage is polled to a CONDITION with a bounded deadline. While the role is not
    yet assumable API Gateway answers 500 "Internal server error", which no accept() here
    admits. ``body`` may be a callable returning fresh bytes per attempt.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        payload = body() if callable(body) else body
        try:
            last = _http(method, url, body=payload, headers=headers)
        except Exception as exc:  # noqa: BLE001 - execute-api DNS/TLS settling
            last = (None, {}, f"connection error: {exc!r}")
        else:
            if accept(last[0], last[2]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"{description} {url} never reached an accepted response within "
                         f"{timeout_s}s. Last: {last[0]} {last[2][:400]!r}")


def _rest_invoke_url(ctx, api_id, stage, path):
    """Invoke URL of a DEPLOYED REST API stage (real AWS host, else the emulator front door)."""
    p = path.lstrip("/")
    return f"{ctx.rest_api_url(api_id, stage)}/{p}"


def _delete_rest_api(ctx, api_id):
    """DeleteRestApi is rate-limited account-wide; retry the throttle, never swallow it."""
    ag = ctx.client("apigateway")
    deadline = time.monotonic() + 150
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() > deadline:
                raise RuntimeError(f"rest api {api_id}: {code}") from exc
            time.sleep(8)


def _create_rest_api(ctx, kind="api"):
    """Create a REGIONAL REST API (teardown registered) and return (api_id, root_resource_id)."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=_xname(ctx, kind), endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xsvc_resource_tags(),
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ctx, api_id))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    return api_id, root_id


def _deploy_stage(ctx, api_id, stage):
    """CreateDeployment + CreateStage (stage teardown registered). Returns the deployment id."""
    ag = ctx.client("apigateway")
    dep_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName=stage, deploymentId=dep_id)
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_stage(restApiId=api_id, stageName=stage))
    return dep_id


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust_service, inline_policy=None):
    """Create an IAM role trusted by trust_service (teardown registered). Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}]}
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                           Path="/sim2real/", Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                            PolicyDocument=json.dumps(inline_policy))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _allow(actions, resource):
    return {"Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]}


def _delete_role(ctx, role_name):
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(f"iam role {role_name}: {exc}") from exc


def _create_state_machine(ctx, definition, sm_type):
    """A state machine (teardown registered) under a fresh, policy-less execution role.

    CreateStateMachine validates that states.amazonaws.com can assume the role, which is
    subject to IAM propagation; the bounded retry is on that one documented message only.
    """
    sfn = ctx.client("stepfunctions")
    role = _create_role(ctx, "states.amazonaws.com")
    name = _xname(ctx, "apigw2-sm")
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role["arn"],
                type=sm_type, tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if ("not authorized to assume" not in str(exc) and "assume the provided role" not in str(exc)) \
                    or time.monotonic() > deadline:
                raise
            time.sleep(4)
    ctx.on_cleanup(lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=arn))
    return arn


def _execution_arn(sm_arn, name):
    """The ARN StartExecution mints for a STANDARD execution named `name`."""
    prefix, sm_name = sm_arn.split(":stateMachine:")
    return f"{prefix}:execution:{sm_name}:{name}"


def _sfn_code(type_field):
    """Step Functions' JSON-1.0 `__type` is `<namespace>#<Code>`; the code is the suffix."""
    return type_field.rsplit("#", 1)[-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
