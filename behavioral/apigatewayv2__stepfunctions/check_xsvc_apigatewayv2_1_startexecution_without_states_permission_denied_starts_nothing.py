"""xsvc-apigatewayv2-1-startexecution-without-states-permission-denied-starts-nothing."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigatewayv2-1-startexecution-without-states-permission-denied-starts-nothing"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "stepfunctions"]

_PASS_THROUGH = {
    "StartAt": "Echo",
    "States": {"Echo": {"Type": "Pass", "End": True}},
}


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A StartExecution route whose role lacks states:StartExecution is refused and starts nothing
    (ExecutionDoesNotExist), while a permitted sibling route starts executions; granting the one
    missing permission makes the refused route start one with its posted body as input."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    sm_arn = _create_state_machine(ctx, _PASS_THROUGH, sm_type="STANDARD")
    sm_name = sm_arn.rsplit(":", 1)[-1]

    # Refused role FIRST, so its trust policy has propagated by the time the control route works.
    # It holds a real states permission — just not StartExecution.
    denied_role_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["states:DescribeStateMachine"], "Resource": sm_arn}
            ],
        },
    )
    denied_role_name = denied_role_arn.rsplit("/", 1)[-1]
    allowed_role_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["states:StartExecution"], "Resource": sm_arn}
            ],
        },
    )
    urls = _http_api_with_subtype(
        ctx,
        subtype="StepFunctions-StartExecution",
        routes=[("/allowed", allowed_role_arn), ("/denied", denied_role_arn)],
        request_parameters={
            "StateMachineArn": sm_arn,
            "Name": "$request.header.x-execution-name",
            "Input": "$request.body",
        },
    )
    marker = ctx.unique_name("sim2real-xsvc-order-")

    def _arn(name):
        return f"arn:aws:states:{ctx.region}:{account}:execution:{sm_name}:{name}"

    def _post(path, name, *, poll):
        body = json.dumps({"orderId": marker, "leg": name}).encode()
        headers = {"Content-Type": "application/json", "x-execution-name": name}
        if poll:
            return _poll_http(
                urls[path], method="POST", body=body, headers=headers,
                accept=lambda s: s == 200, description=f"POST {path} for {name}",
            )
        return _http_routed("POST", urls[path], body=body, headers=headers)

    def _execution_names():
        names = set()
        for page in sfn.get_paginator("list_executions").paginate(stateMachineArn=sm_arn):
            names.update(e["name"] for e in page["executions"])
        return names

    # Beat 1 — the control route starts an execution (absorbs IAM propagation).
    control_1 = ctx.unique_name("sim2real-xsvc-ctl1-")
    status, _, text = _post("/allowed", control_1, poll=True)
    assert json.loads(text).get("executionArn") == _arn(control_1), (
        f"control execution ARN mismatch: {text[:300]!r}"
    )

    # Beat 2 — the refused request: exact status and error code.
    denied_name = ctx.unique_name("sim2real-xsvc-deny-")
    bad_status, _, bad_text = _post("/denied", denied_name, poll=False)
    assert bad_status == 400, (
        f"a StartExecution integration whose role lacks states:StartExecution must surface Step "
        f"Functions' own refusal as 400, got {bad_status}: {bad_text[:300]!r}"
    )
    bad_body = json.loads(bad_text)
    # The error code is read the way every SDK reads it: the part of __type after any '#'
    # (observed: "com.amazon.coral.service#AccessDeniedException").
    assert (bad_body.get("__type") or "").rsplit("#", 1)[-1] == "AccessDeniedException", (
        f"the refusal must be Step Functions' AccessDeniedException passed through, got "
        f"{bad_text[:300]!r}"
    )
    message = bad_body.get("message") or bad_body.get("Message") or ""
    assert denied_role_name in message and "states:StartExecution" in message, (
        f"the AccessDenied message must name the route's own role {denied_role_name!r} and "
        f"states:StartExecution, got {message!r}"
    )

    # Beat 3 — differential barrier: a control execution started AFTER the refusal is listed,
    # and the refused one is not — neither by listing nor by its exact ARN.
    control_2 = ctx.unique_name("sim2real-xsvc-ctl2-")
    status, _, text = _post("/allowed", control_2, poll=False)
    assert status == 200, f"the control route must still start executions, got {status}: {text!r}"
    names = _poll_until(
        _execution_names,
        lambda n: control_2 in n,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"control execution {control_2!r} appearing in ListExecutions",
    )
    assert names == {control_1, control_2}, (
        f"this state machine must hold exactly the two control executions "
        f"{sorted([control_1, control_2])!r}, got {sorted(names)!r}"
    )
    try:
        sfn.describe_execution(executionArn=_arn(denied_name))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    else:
        raise AssertionError(
            f"the refused request must start no execution, but {_arn(denied_name)!r} exists"
        )
    assert code == "ExecutionDoesNotExist", (
        f"DescribeExecution on the refused request's ARN must be ExecutionDoesNotExist, got {code!r}"
    )

    # Beat 4 — repair the ONE missing permission; the same route now starts its execution.
    iam.put_role_policy(
        RoleName=denied_role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["states:StartExecution"], "Resource": sm_arn}
                ],
            }
        ),
    )
    repaired = ctx.unique_name("sim2real-xsvc-fixd-")
    status, _, text = _post("/denied", repaired, poll=True)
    assert json.loads(text).get("executionArn") == _arn(repaired), (
        f"after the grant the refused route must start {_arn(repaired)!r}, got {text[:300]!r}"
    )
    got = sfn.describe_execution(executionArn=_arn(repaired))["input"]
    assert json.loads(got) == {"orderId": marker, "leg": repaired}, (
        f"the repaired route's execution input must be its posted body, got {got!r}"
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
