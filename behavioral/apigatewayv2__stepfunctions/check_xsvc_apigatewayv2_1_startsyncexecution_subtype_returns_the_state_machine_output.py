"""xsvc-apigatewayv2-1-startsyncexecution-subtype-returns-the-state-machine-output."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigatewayv2-1-startsyncexecution-subtype-returns-the-state-machine-output"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "stepfunctions"]

_PRICE_ORDER = {
    "Comment": "Price an order, or reject a non-positive quantity.",
    "StartAt": "CheckQuantity",
    "States": {
        "CheckQuantity": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.quantity", "NumericLessThan": 1, "Next": "Reject"}],
            "Default": "Price",
        },
        "Price": {
            "Type": "Pass",
            "Parameters": {
                "orderId.$": "$.orderId",
                "total.$": "States.MathAdd($.subtotal, $.shipping)",
                "summary.$": "States.Format('{} x{}', $.orderId, $.quantity)",
            },
            "End": True,
        },
        "Reject": {"Type": "Fail", "Error": "InvalidQuantity", "Cause": "quantity must be >= 1"},
    },
}


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A POST to a StartSyncExecution route returns SUCCEEDED with the workflow's computed output
    (intrinsics, not an input copy), the posted input and an express executionArn; a POST that
    hits the Fail state returns FAILED with that state's error and cause and no output."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    sm_arn = _create_state_machine(ctx, _PRICE_ORDER, sm_type="EXPRESS")
    sm_name = sm_arn.rsplit(":", 1)[-1]
    role_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["states:StartSyncExecution"], "Resource": sm_arn}
            ],
        },
    )
    urls = _http_api_with_subtype(
        ctx,
        subtype="StepFunctions-StartSyncExecution",
        routes=[("/price", role_arn)],
        request_parameters={"StateMachineArn": sm_arn, "Input": "$request.body"},
    )
    marker = ctx.unique_name("sim2real-xsvc-order-")

    posted = json.dumps({"orderId": marker, "quantity": 3, "subtotal": 40, "shipping": 2})
    status, _, text = _poll_http(
        urls["/price"],
        method="POST",
        body=posted.encode(),
        headers={"Content-Type": "application/json"},
        accept=lambda s: s == 200,
        description="POST /price reaching the StepFunctions-StartSyncExecution integration",
    )
    resp = json.loads(text)
    assert resp.get("status") == "SUCCEEDED", (
        f"the synchronous execution must report SUCCEEDED, got {resp.get('status')!r}: {text[:400]!r}"
    )
    output = json.loads(resp.get("output") or "null")
    expected = {"orderId": marker, "total": 42, "summary": f"{marker} x3"}
    assert output == expected, (
        f"the HTTP response must carry the state machine's computed output {expected!r}, got "
        f"{resp.get('output')!r}"
    )
    assert resp.get("input") == posted, (
        f"the response input must be the posted body {posted!r}, got {resp.get('input')!r}"
    )
    prefix = f"arn:aws:states:{ctx.region}:{account}:express:{sm_name}:"
    assert (resp.get("executionArn") or "").startswith(prefix), (
        f"the executionArn must be an express execution of this state machine ({prefix}...), got "
        f"{resp.get('executionArn')!r}"
    )
    assert resp.get("stateMachineArn") == sm_arn, (
        f"the response stateMachineArn must be {sm_arn!r}, got {resp.get('stateMachineArn')!r}"
    )

    # The Fail branch: the workflow's failure is reported in the body, carrying its own error.
    bad = json.dumps({"orderId": marker, "quantity": 0, "subtotal": 40, "shipping": 2})
    f_status, _, f_text = _http_routed(
        "POST", urls["/price"], body=bad.encode(), headers={"Content-Type": "application/json"}
    )
    assert f_status == 200, (
        f"a workflow that FAILS still completes the synchronous call; expected HTTP 200, got "
        f"{f_status}: {f_text[:400]!r}"
    )
    failed = json.loads(f_text)
    assert failed.get("status") == "FAILED", (
        f"the Fail branch must report status FAILED, got {failed.get('status')!r}: {f_text[:400]!r}"
    )
    assert (failed.get("error"), failed.get("cause")) == ("InvalidQuantity", "quantity must be >= 1"), (
        f"the failure must carry the Fail state's own error and cause, got "
        f"({failed.get('error')!r}, {failed.get('cause')!r})"
    )
    assert "output" not in failed, (
        f"a FAILED synchronous execution must carry no output, got {failed.get('output')!r}"
    )


def _create_state_machine(ctx, definition, *, sm_type):
    """A state machine whose role needs no permissions (Pass/Choice/Fail only). CreateStateMachine
    retries the one error IAM propagation of the fresh execution role can produce."""
    role_arn = _create_role(ctx, "states.amazonaws.com")
    sfn = ctx.client("stepfunctions")
    name = _xname(ctx, "sm")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(
            lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=arn)
        )
        return arn
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _http_api_with_subtype(ctx, *, subtype, routes, request_parameters):
    """An HTTP API with one POST route per (path, CredentialsArn) pair, each integrated with the
    given first-class Step Functions subtype. Returns {path: invoke_url}."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-sfn"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    urls = {}
    for path, role_arn in routes:
        integration_id = agw.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationSubtype=subtype,
            PayloadFormatVersion="1.0",
            CredentialsArn=role_arn,
            RequestParameters=request_parameters,
        )["IntegrationId"]
        stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
        assert stored.get("IntegrationSubtype") == subtype, (
            f"GetIntegration must report subtype {subtype!r}, got "
            f"{stored.get('IntegrationSubtype')!r}"
        )
        agw.create_route(
            ApiId=api_id, RouteKey=f"POST {path}", Target=f"integrations/{integration_id}"
        )
        urls[path] = _v2_invoke_url(ctx, api["ApiEndpoint"], "$default", path)
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )
    return urls



_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _http_routed(method, url, body=None, headers=None, timeout_s=60.0):
    """One logical request to a route that is ALREADY known to be deployed (an earlier request to
    this API succeeded). A fresh $default auto-deployment is eventually consistent across the
    gateway's fleet, so a request can still land on a node that answers the API's own
    route-not-found 404 ``{"message":"Not Found"}``; that answer means the integration was never
    invoked, so retrying it repeats nothing. Any other status is returned as the result."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, hdrs, text = _http(method, url, body=body, headers=headers)
        if not (status == 404 and text.strip() == '{"message":"Not Found"}'):
            return status, hdrs, text
        if time.monotonic() >= deadline:
            return status, hdrs, text
        time.sleep(2.0)


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=180.0,
    interval_s=5.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout.

    This also absorbs IAM propagation: a brand-new CredentialsArn is not immediately usable by
    API Gateway, which surfaces as a 5xx on the first requests.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers, timeout_s=20)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _v2_invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage, from ``ctx.stage_url``."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
