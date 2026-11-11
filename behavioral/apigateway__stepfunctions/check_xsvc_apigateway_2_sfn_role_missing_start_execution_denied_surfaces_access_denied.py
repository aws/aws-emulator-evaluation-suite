"""xsvc-apigateway-2-sfn-role-missing-start-execution-denied-surfaces-access-denied."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-2-sfn-role-missing-start-execution-denied-surfaces-access-denied"
GROUP = "permission-chain"
SERVICES = ["apigateway", "stepfunctions"]

_DEFINITION = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}
_REQUEST_TEMPLATE = (
    '{"stateMachineArn": "__SM__", "name": "$input.params(\'x-execution-name\')", '
    '"input": "$util.escapeJavaScript($input.json(\'$\'))"}'
)
_OK_TEMPLATE = '{"started": true, "executionArn": "$input.path(\'$.executionArn\')"}'
_ERR_TEMPLATE = ('{"started": false, "surfacedType": "$input.path(\'$.__type\')", '
                 '"surfacedMessage": $input.json(\'$.Message\')}')


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An integration role without states:StartExecution is refused with AccessDeniedException, surfaced
    as 403 with no execution, while a granted twin starts one; granting the action makes it start."""
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    sm_arn = _create_state_machine(ctx, _DEFINITION, "STANDARD")
    granted = _create_role(ctx, "apigateway.amazonaws.com",
                           inline_policy=_allow(["states:StartExecution"], sm_arn))
    denied = _create_role(ctx, "apigateway.amazonaws.com",
                          inline_policy=_allow(["states:DescribeStateMachine"], sm_arn))

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw2-sfndeny")
    for path, role in (("granted", granted), ("denied", denied)):
        rid = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart=path)["id"]
        ag.put_method(restApiId=api_id, resourceId=rid, httpMethod="POST",
                      authorizationType="NONE",
                      requestParameters={"method.request.header.x-execution-name": True})
        ag.put_integration(
            restApiId=api_id, resourceId=rid, httpMethod="POST", type="AWS",
            integrationHttpMethod="POST",
            uri=f"arn:aws:apigateway:{ctx.region}:states:action/StartExecution",
            credentials=role["arn"], passthroughBehavior="NEVER",
            requestTemplates={"application/json": _REQUEST_TEMPLATE.replace("__SM__", sm_arn)},
        )
        for code in ("200", "403"):
            ag.put_method_response(restApiId=api_id, resourceId=rid, httpMethod="POST",
                                   statusCode=code)
        ag.put_integration_response(restApiId=api_id, resourceId=rid, httpMethod="POST",
                                    statusCode="200",
                                    responseTemplates={"application/json": _OK_TEMPLATE})
        ag.put_integration_response(restApiId=api_id, resourceId=rid, httpMethod="POST",
                                    statusCode="403", selectionPattern="4\\d{2}",
                                    responseTemplates={"application/json": _ERR_TEMPLATE})
    _deploy_stage(ctx, api_id, "live")
    url_ok = _rest_invoke_url(ctx, api_id, "live", "/granted")
    url_no = _rest_invoke_url(ctx, api_id, "live", "/denied")
    tag = ctx.unique_name("x-")
    names = {k: f"{tag}-{k}" for k in ("control", "denied", "barrier", "repaired")}

    def hdrs(kind):
        return {"Content-Type": "application/json", "x-execution-name": names[kind]}

    def listed():
        return sorted(e["name"] for p in sfn.get_paginator("list_executions").paginate(
            stateMachineArn=sm_arn) for e in p["executions"])

    # Beat 1 - positive control.
    _, _, t = _poll_http(url_ok, accept=lambda s, t: s == 200 and '"started": true' in t,
                         body=b'{"k": "control"}', headers=hdrs("control"),
                         description="granted twin route")
    assert json.loads(t)["executionArn"] == _execution_arn(sm_arn, names["control"]), t

    # Beats 2+3 - the denied route, polled only past the role's assume-propagation window.
    st, _, t = _poll_http(url_no, accept=lambda s, t: s in (200, 403), body=b'{"k": "denied"}',
                          headers=hdrs("denied"), description="denied route")
    assert st == 403, f"role without states:StartExecution was NOT refused: {st} {t[:300]!r}"
    err = json.loads(t)
    assert err["started"] is False and _sfn_code(err["surfacedType"]) == "AccessDeniedException", (
        f"Step Functions' refusal was surfaced as {err!r}, expected AccessDeniedException")
    want = (f"User: {_assumed_role_arn(denied['arn'])}/{_APIGW_SESSION} is not authorized to "
            f"perform: states:StartExecution on resource: {sm_arn} because no identity-based "
            f"policy allows the states:StartExecution action")
    assert err["surfacedMessage"] == want, (
        f"Step Functions' refusal message was {err['surfacedMessage']!r}, expected {want!r}")

    # Beat 4 - effect absent at Step Functions, after a later granted start is visible.
    st, _, t = _http("POST", url_ok, body=b'{"k": "barrier"}', headers=hdrs("barrier"))
    assert st == 200, f"granted twin stopped starting executions: {st} {t[:300]!r}"
    seen = _poll_until(listed, lambda n: names["barrier"] in n, timeout_s=60.0, interval_s=2.0,
                       description="barrier execution listed")
    assert seen == sorted([names["control"], names["barrier"]]), (
        f"ListExecutions shows {seen!r}; the refused execution must not exist")
    denied_arn = _execution_arn(sm_arn, names["denied"])
    code, message = _error(lambda: sfn.describe_execution(executionArn=denied_arn))
    assert code == "ExecutionDoesNotExist", (
        f"DescribeExecution of the refused name returned {code!r}, expected ExecutionDoesNotExist")
    assert message == f"Execution Does Not Exist: '{denied_arn}'", (
        f"DescribeExecution of the refused name said {message!r}")

    # Beats 5+6 - grant the one missing action; the identical route starts an execution.
    iam.put_role_policy(RoleName=denied["name"], PolicyName="inline", PolicyDocument=json.dumps(
        _allow(["states:DescribeStateMachine", "states:StartExecution"], sm_arn)))
    _, _, t = _poll_http(url_no, accept=lambda s, t: s == 200 and '"started": true' in t,
                         body=b'{"k": "repaired"}', headers=hdrs("repaired"), timeout_s=120.0,
                         description="denied route after granting states:StartExecution")
    arn = json.loads(t)["executionArn"]
    assert arn == _execution_arn(sm_arn, names["repaired"]), f"repaired start returned {arn!r}"
    desc = sfn.describe_execution(executionArn=arn)
    assert json.loads(desc["input"]) == {"k": "repaired"}, f"repaired input {desc['input']!r}"
    seen = _poll_until(listed, lambda n: names["repaired"] in n, timeout_s=60.0, interval_s=2.0,
                       description="repaired execution listed")
    assert seen == sorted([names["control"], names["barrier"], names["repaired"]]), (
        f"ListExecutions shows {seen!r}; the refused name {names['denied']!r} must never appear")



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


# The session name API Gateway uses when it assumes an integration's credentials role.
_APIGW_SESSION = "BackplaneAssumeRoleSession"


def _assumed_role_arn(role_arn):
    """`arn:aws:iam::<acct>:role/<name>` -> `arn:aws:sts::<acct>:assumed-role/<name>`."""
    prefix, name = role_arn.split(":role/", 1)
    return prefix.replace(":iam::", ":sts::") + ":assumed-role/" + name.rsplit("/", 1)[-1]


def _sfn_code(type_field):
    """Step Functions' JSON-1.0 `__type` is `<namespace>#<Code>`; the code is the suffix."""
    return type_field.rsplit("#", 1)[-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
