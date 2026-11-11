"""deep-apigateway-1-apigw-methodsetting-logging-level-and-data-trace-gate-execution-logs."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags

CHECK = "deep-apigateway-1-apigw-methodsetting-logging-level-and-data-trace-gate-execution-logs"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "logs"]

# Whole-check budget: three MethodSetting flips that each take ~30 s to settle across the
# gateway fleet, plus CloudWatch Logs delivery latency for every phase.
_BUDGET_S = 1200
_PHASE_TIMEOUT_S = 240
_DELIVERY_TIMEOUT_S = 240

_CONFIG_ERROR = "Execution failed due to configuration error"
_INFO_LINE = "Starting execution for request"
_TRACE_REQ = "Endpoint request body after transformations: "
_TRACE_RESP_IN = "Endpoint response body before transformations: "
_TRACE_RESP_OUT = "Method response body after transformations: "
_TRACE_QS = "Method request query string: "
_PUSH_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"


@tags("axis:negative-delivery", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "resource:account-singleton:apigateway-account")
def run(ctx) -> None:
    """loggingLevel and dataTraceEnabled decide which requests reach the execution log group and what
    they carry: OFF logs nothing, ERROR logs only the failing request, INFO logs the success trace,
    and data trace adds the transformed request body and the method response body."""
    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")
    t0_ms = int(time.time() * 1000) - 60_000

    # Registered FIRST so LIFO runs it LAST -- after the API is gone, when no further delivery can
    # recreate the group.
    holder: dict = {}
    ctx.on_cleanup(lambda: _reap_log_group(logs, holder.get("group")))

    table = _create_counter_table(ctx)
    role_arn = _create_integration_role(ctx, table)
    api_id = _create_api(ctx, table, role_arn)
    stage = "logs"
    group = f"API-Gateway-Execution-Logs_{api_id}/{stage}"
    holder["group"] = group
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    base = ctx.rest_api_url(api_id, stage)
    ok_url, err_url = f"{base}/count", f"{base}/broken"

    # The account-level CloudWatch role is the precondition for ANY execution logging. Hold it
    # constant for the whole check so the stage setting is the only variable.
    cw_role = _create_push_role(ctx)
    _set_account_cloudwatch_role(ctx, cw_role)

    st, _, b = _wait_for_status(ok_url, 200, timeout_s=180)
    assert st == 200, f"/count never answered 200: {st} {b!r}"
    st, _, b = _wait_for_status(err_url, 500, timeout_s=180)
    assert st == 500, f"/broken should fail with a 500 configuration error, got {st} {b!r}"

    def fire(url: str, want: int) -> dict:
        marker = uuid.uuid4().hex[:12]
        st, hdrs, body = _get(f"{url}?m={marker}")
        assert st == want, f"GET {url}?m={marker} returned {st} {body!r}, expected {want}"
        rid = hdrs.get("x-amzn-requestid")
        assert rid, f"no x-amzn-RequestId on response headers {hdrs!r}"
        return {"rid": rid, "marker": marker, "body": body}

    # ---- OFF ---------------------------------------------------------------------------------
    off = [fire(ok_url, 200) for _ in range(2)] + [fire(err_url, 500) for _ in range(2)]

    # ---- ERROR -------------------------------------------------------------------------------
    _set_logging(apigw, api_id, stage, level="ERROR", data_trace=False)
    error_ok: list[dict] = []
    err_barrier = _until_logged(
        logs, group, t0_ms,
        fire=lambda: (error_ok.append(fire(ok_url, 200)), fire(err_url, 500))[1],
        want=lambda msgs, req: any(_CONFIG_ERROR in m for m in msgs),
        timeout_s=_PHASE_TIMEOUT_S, what="ERROR level never delivered the configuration-error line")
    error_ok_after = [fire(ok_url, 200) for _ in range(3)]

    # ---- INFO, no data trace -------------------------------------------------------------------
    _set_logging(apigw, api_id, stage, level="INFO", data_trace=False)
    info_barrier = _until_logged(
        logs, group, t0_ms, fire=lambda: fire(ok_url, 200),
        want=lambda msgs, req: any(_INFO_LINE in m for m in msgs),
        timeout_s=_PHASE_TIMEOUT_S, what="INFO level never delivered the execution trace")
    info_after = [fire(ok_url, 200) for _ in range(3)]

    # ---- INFO + data trace ----------------------------------------------------------------------
    _set_logging(apigw, api_id, stage, level="INFO", data_trace=True)
    trace_barrier = _until_logged(
        logs, group, t0_ms, fire=lambda: fire(ok_url, 200),
        want=lambda msgs, req: any(_TRACE_REQ in m and f'"M{req["marker"]}"' in m for m in msgs),
        timeout_s=_PHASE_TIMEOUT_S, what="dataTraceEnabled never delivered the transformed request body")
    # Delivery barrier for the absences: events for one MORE data-trace request, fired after
    # every request whose absence is asserted below, must have arrived.
    _until_logged(
        logs, group, t0_ms, fire=lambda: fire(ok_url, 200),
        want=lambda msgs, req: any(_TRACE_REQ in m and f'"M{req["marker"]}"' in m for m in msgs),
        timeout_s=_DELIVERY_TIMEOUT_S, what="delivery barrier request never logged")

    by_rid = _events_by_rid(logs, group, t0_ms)

    # OFF: nothing at all, success or failure.
    for req in off:
        assert not by_rid.get(req["rid"]), (
            f"logging OFF still delivered {len(by_rid[req['rid']])} events for {req['rid']}: "
            f"{by_rid[req['rid']][:3]!r}"
        )
    # ERROR: the failure is logged, and only at ERROR verbosity; the success is not logged.
    msgs = err_barrier["messages"]
    assert any(_CONFIG_ERROR in m for m in msgs), f"ERROR-level failure events: {msgs!r}"
    assert not any(_INFO_LINE in m for m in msgs), (
        f"ERROR level delivered an INFO line for the failing request: {msgs!r}"
    )
    for req in error_ok + error_ok_after:
        assert not by_rid.get(req["rid"]), (
            f"ERROR level delivered events for a SUCCESSFUL request {req['rid']}: "
            f"{by_rid[req['rid']][:3]!r}"
        )
    # INFO without data trace: execution trace present, data-trace lines absent.
    msgs = info_barrier["messages"]
    assert any(_INFO_LINE in m for m in msgs), f"INFO events: {msgs!r}"
    for req in [info_barrier["req"]] + info_after:
        got = by_rid.get(req["rid"], [])
        leaked = [m for m in got if _TRACE_REQ in m or _TRACE_QS in m or req["marker"] in m]
        assert not leaked, (
            f"dataTraceEnabled=false still delivered data-trace content for {req['rid']}: {leaked!r}"
        )
    # INFO with data trace: transformed body with THIS request's marker, the backend response,
    # and the method response body exactly as the client received it.
    req, msgs = trace_barrier["req"], trace_barrier["messages"]
    assert any(_INFO_LINE in m for m in msgs), f"INFO+trace lost the INFO line: {msgs!r}"
    transformed = [m for m in msgs if _TRACE_REQ in m]
    assert len(transformed) == 1 and f'"M{req["marker"]}"' in transformed[0] and table in transformed[0], (
        f"transformed request body should carry table {table!r} and marker M{req['marker']}: {transformed!r}"
    )
    backend = [m for m in msgs if _TRACE_RESP_IN in m]
    n = json.loads(req["body"])["n"]
    assert len(backend) == 1 and f'"N":"{n}"' in backend[0], (
        f"logged backend response should carry the counter value {n!r}: {backend!r}"
    )
    out = [m.split(_TRACE_RESP_OUT, 1)[1] for m in msgs if _TRACE_RESP_OUT in m]
    assert out == [req["body"]], (
        f"logged method response body {out!r} != body the client received {req['body']!r}"
    )


def _get(url: str, timeout_s: float = 15.0) -> tuple[int, dict, str]:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read().decode()


def _wait_for_status(url: str, want: int, timeout_s: float) -> tuple[int, dict, str]:
    deadline = time.monotonic() + timeout_s
    last: tuple = (None, {}, "")
    while time.monotonic() < deadline:
        try:
            last = _get(url)
        except (urllib.error.URLError, TimeoutError) as exc:  # DNS / connect propagation
            last = (None, {}, repr(exc))
        if last[0] == want:
            return last
        time.sleep(3)
    return last


def _events_by_rid(logs, group: str, start_ms: int) -> dict[str, list[str]]:
    """Every event in the group since start, indexed by the `(requestId)` prefix API Gateway
    puts on each execution-log line. Paginated: a sibling stage cannot write here, but one
    request alone can emit 20+ lines."""
    out: dict[str, list[str]] = {}
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
                logGroupName=group, startTime=start_ms):
            for ev in page.get("events", []):
                msg = ev["message"]
                if msg.startswith("(") and ")" in msg:
                    out.setdefault(msg[1:msg.index(")")], []).append(msg)
    except logs.exceptions.ResourceNotFoundException:
        pass
    return out


def _until_logged(logs, group: str, start_ms: int, fire, want, timeout_s: float, what: str) -> dict:
    """Fire a request every few seconds until one of them has events satisfying `want`.

    Returns {"req", "messages"} for the FIRST request that did -- the request that proves the
    setting is in force on the node that served it.
    """
    deadline = time.monotonic() + timeout_s
    fired: list[dict] = []
    last_fire = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() - last_fire >= 5:
            fired.append(fire())
            last_fire = time.monotonic()
        by_rid = _events_by_rid(logs, group, start_ms)
        for req in fired:
            msgs = by_rid.get(req["rid"], [])
            if msgs and want(msgs, req):
                return {"req": req, "messages": msgs}
        time.sleep(4)
    raise AssertionError(f"{what} within {timeout_s}s ({len(fired)} requests fired)")


def _set_logging(apigw, api_id: str, stage: str, level: str, data_trace: bool) -> None:
    apigw.update_stage(restApiId=api_id, stageName=stage, patchOperations=[
        {"op": "replace", "path": "/*/*/logging/loglevel", "value": level},
        {"op": "replace", "path": "/*/*/logging/dataTrace", "value": "true" if data_trace else "false"},
    ])
    got = apigw.get_stage(restApiId=api_id, stageName=stage)["methodSettings"]["*/*"]
    assert got.get("loggingLevel") == level and got.get("dataTraceEnabled") is data_trace, (
        f"GetStage did not echo loggingLevel={level} dataTraceEnabled={data_trace}: {got!r}"
    )


def _reap_log_group(logs, group: str | None) -> None:
    """Delete the execution log group, then watch for a late flush recreating it."""
    if not group:
        return
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(5)
        if not logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups"):
            return
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_counter_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-xsvc-msett-log-")
    ddb.create_table(TableName=table, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return table


def _delete_table(ddb, table: str) -> None:
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    ddb.delete_table(TableName=table)


def _trust(service: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]})


def _create_integration_role(ctx, table: str) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-xsvc-msett-log-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_trust("apigateway.amazonaws.com"))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="counter", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:UpdateItem",
                       "Resource": f"arn:aws:dynamodb:{ctx.region}:{account}:table/{table}"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="counter"))
    return arn


def _create_push_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-msett-logcw-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_trust("apigateway.amazonaws.com"))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_PUSH_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_PUSH_POLICY))
    return arn


def _set_account_cloudwatch_role(ctx, role_arn: str) -> None:
    """Point the account's API Gateway CloudWatch role at ours; restore exactly the previous
    value on cleanup."""
    apigw = ctx.client("apigateway")
    logs = ctx.client("logs")
    original = apigw.get_account().get("cloudwatchRoleArn") or ""
    # Setting the role makes API Gateway create `/aws/apigateway/welcome` server-side. Reap it
    # only if THIS check caused it (absent beforehand); registered before the restore so LIFO
    # deletes it after the role is reverted.
    welcome = "/aws/apigateway/welcome"
    existed = any(g["logGroupName"] == welcome for g in
                  logs.describe_log_groups(logGroupNamePrefix=welcome).get("logGroups", []))
    if not existed:
        ctx.on_cleanup(lambda: _reap_log_group(logs, welcome))

    def _restore() -> None:
        apigw.update_account(patchOperations=[
            {"op": "replace", "path": "/cloudwatchRoleArn", "value": original}])

    ctx.on_cleanup(_restore)
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            apigw.update_account(patchOperations=[
                {"op": "replace", "path": "/cloudwatchRoleArn", "value": role_arn}])
            return
        except (apigw.exceptions.BadRequestException, apigw.exceptions.TooManyRequestsException) as exc:
            # BadRequest: the new role's trust/policy has not propagated through IAM yet.
            last = exc
            time.sleep(5)
    raise AssertionError(f"could not set the account cloudwatchRoleArn within 120s: {last!r}")


def _create_api(ctx, table: str, role_arn: str) -> str:
    """GET /count -> DynamoDB UpdateItem (marker from ?m= into the transformed body);
    GET /broken -> same integration with a credentials role that does not exist (500)."""
    apigw = ctx.client("apigateway")
    account = ctx.client("sts").get_caller_identity()["Account"]
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-xsvc-msett-log-"),
                                   endpointConfiguration={"types": ["REGIONAL"]})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    template = json.dumps({
        "TableName": table, "Key": {"pk": {"S": "counter"}},
        "UpdateExpression": "ADD n :one SET lastm = :m",
        "ExpressionAttributeValues": {":one": {"N": "1"}, ":m": {"S": "M$input.params('m')"}},
        "ReturnValues": "UPDATED_NEW"})
    missing_role = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-xsvc-msett-absent-')}"
    for path, creds in (("count", role_arn), ("broken", missing_role)):
        res = apigw.create_resource(restApiId=api_id, parentId=root, pathPart=path)["id"]
        apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="GET", authorizationType="NONE")
        apigw.put_integration(restApiId=api_id, resourceId=res, httpMethod="GET", type="AWS",
                              integrationHttpMethod="POST",
                              uri=f"arn:aws:apigateway:{ctx.region}:dynamodb:action/UpdateItem",
                              credentials=creds, passthroughBehavior="NEVER",
                              requestTemplates={"application/json": template})
        apigw.put_method_response(restApiId=api_id, resourceId=res, httpMethod="GET", statusCode="200")
        apigw.put_integration_response(
            restApiId=api_id, resourceId=res, httpMethod="GET", statusCode="200",
            responseTemplates={"application/json": '{"n": "$input.path(\'$.Attributes.n.N\')"}'})
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
