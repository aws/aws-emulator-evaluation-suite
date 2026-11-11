"""appsync-field-log-level-all-delivers-tracing-for-the-response-request-id."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-field-log-level-all-delivers-tracing-for-the-response-request-id"
GROUP = "observability"
SERVICES = ["appsync", "logs"]

SDL = """schema { query: Query }
type Query {
    probe(msg: String!): String
}
"""

JS_ECHO = (
    "import { runtime } from '@aws-appsync/utils';\n"
    "export function request(ctx) {\n  runtime.earlyReturn(ctx.args.msg);\n  return {};\n}\n"
    "export function response(ctx) {\n  return ctx.result;\n}\n"
)

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
LOG_TIMEOUT_S = 300.0
_ABSENCE_HOLD_S = 9.0


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition",
                ctx=None):
    """Bounded retry that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body, response_headers)."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw, hdrs = resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        status, raw, hdrs = exc.code, exc.read().decode("utf-8", "replace"), dict(exc.headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}, {}
    try:
        return status, (json.loads(raw) if raw else {}), hdrs
    except ValueError:
        return status, {"raw": raw}, hdrs


def _header(headers, name):
    """A response header, case-insensitively -- HTTP header case is not guaranteed on the wire."""
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    return lowered.get(name.lower())


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(
                f"role {role_name} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _create_logging_role(ctx):
    """The role AppSync assumes to publish to CloudWatch Logs, as the monitoring guide prescribes.

    IAM has no condition for trust propagation, so CreateGraphqlApi retries on role rejection.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-logs-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "appsync.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="push-to-logs",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                      "logs:PutLogEvents"],
                           "Resource": "*"}],
        }),
    )
    return arn


def _retry_on_role_propagation(fn, *, timeout_s=45.0, interval_s=3.0, description="operation"):
    """Retry ``fn`` while AppSync rejects the just-created logging role during IAM propagation.

    Bounded; raises the last error on timeout."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            msg = exc.response.get("Error", {}).get("Message", "") or ""
            if code == "BadRequestException" and "role" in msg.lower():
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"{description} still rejected the logging role after {timeout_s}s: {last_err}"
    )


def _delete_log_group_when_it_exists(ctx, group, timeout_s=120.0):
    """Delete a service-created log group, waiting for it to appear first.

    AppSync creates the group on the first logged request, which can land after the body ends.
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group} not deleted: {code}") from exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"log group {group} never materialised within {timeout_s}s"
                ) from exc
            time.sleep(2.0)


def _events_for(ctx, group, request_id):
    """Every parsed AppSync log event in ``group`` naming ``request_id``; [] if no group."""
    logs = ctx.client("logs")
    out = []
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, filterPattern=f'"{request_id}"'
        )
        for page in pages:
            for event in page.get("events", []):
                try:
                    out.append(json.loads(event["message"]))
                except ValueError:
                    out.append({"logType": "__unparsed__", "raw": event["message"]})
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []
        raise
    return [e for e in out if e.get("requestId") == request_id]


def _all_tracing_log_types(ctx, group):
    """Every ``Tracing`` event in ``group``, regardless of request id; [] if the group is absent."""
    logs = ctx.client("logs")
    found = []
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, filterPattern='"Tracing"'
        )
        for page in pages:
            for event in page.get("events", []):
                try:
                    parsed = json.loads(event["message"])
                except ValueError:
                    continue
                if parsed.get("logType") == "Tracing":
                    found.append(parsed)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []
        raise
    return found


def _logged_api(ctx, svc, sdl, field_log_level, logging_role_arn):
    """A GraphQL API with logConfig, an ACTIVE schema, a NONE-backed resolver on Query.probe and
    an api key. Returns (api_id, uri, key, resolver_arn)."""
    api = _retry_on_role_propagation(
        lambda: svc.create_graphql_api(
            name=ctx.unique_name("sim2real-behav-appsync-api-"),
            authenticationType="API_KEY",
            logConfig={
                "fieldLogLevel": field_log_level,
                "cloudWatchLogsRoleArn": logging_role_arn,
                "excludeVerboseContent": False,
            },
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        ),
        description=f"CreateGraphqlApi for the {field_log_level} api",
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    ctx.on_cleanup(
        lambda: _delete_log_group_when_it_exists(ctx, f"/aws/appsync/apis/{api_id}")
    )
    stored = (api.get("logConfig") or {}).get("fieldLogLevel")
    assert stored == field_log_level, (
        f"CreateGraphqlApi did not store the log level: expected {field_log_level!r}, got "
        f"{stored!r} in {api.get('logConfig')!r}"
    )
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=_budget_s(ctx, 180.0), interval_s=1.0,
        description=f"StartSchemaCreation on the {field_log_level} api to reach a terminal status",
        ctx=ctx,
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed on the {field_log_level} api: got "
        f"{status['status']!r} details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the {field_log_level} api exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"

    ds_name = _alnum(ctx, "ds")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    resolver = svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="probe", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO,
    )["resolver"]
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="probe"))
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav logging key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key, resolver["resolverArn"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """fieldLogLevel ALL delivers a RequestSummary and a Tracing event keyed to the response's
    x-amzn-RequestId, matching the SDL and CreateResolver's ARN; a twin NONE api logs no Tracing.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/monitoring.html
    """
    svc = ctx.client("appsync")
    logging_role = _create_logging_role(ctx)

    all_api, all_url, all_key, all_resolver_arn = _logged_api(ctx, svc, SDL, "ALL", logging_role)
    none_api, none_url, none_key, _ = _logged_api(ctx, svc, SDL, "NONE", logging_role)
    all_group = f"/aws/appsync/apis/{all_api}"
    none_group = f"/aws/appsync/apis/{none_api}"

    marker = ctx.unique_name("logprobe-")
    document = "query P($m: String!) { probe(msg: $m) }"

    def _ask(url, key):
        return _post_json(ctx, url, {"x-api-key": key},
                          {"query": document, "variables": {"m": marker}})

    for url, key, label in ((all_url, all_key, "ALL"), (none_url, none_key, "NONE")):
        _poll_until(
            lambda _u=url, _k=key: _ask(_u, _k),
            lambda res: res[0] == 200 and (res[1].get("data") or {}).get("probe") == marker,
            timeout_s=_budget_s(ctx, 180.0), interval_s=1.0,
            description=f"the {label} api's resolver to answer on the live endpoint", ctx=ctx,
        )

    t0 = time.monotonic()
    all_status, all_body, all_headers = _ask(all_url, all_key)
    none_status, none_body, none_headers = _ask(none_url, none_key)

    assert all_status == 200 and not all_body.get("errors"), (
        f"the ALL api's measured request did not succeed: {all_status!r} {all_body!r}"
    )
    assert none_status == 200 and not none_body.get("errors"), (
        f"the NONE api's twin request did not succeed, so it is not a control: {none_status!r} "
        f"{none_body!r}"
    )

    all_request_id = _header(all_headers, "x-amzn-RequestId")
    none_request_id = _header(none_headers, "x-amzn-RequestId")
    assert all_request_id, (
        f"every GraphQL response must carry x-amzn-RequestId -- it is the documented correlator "
        f"for the logs; got headers {sorted(all_headers)!r}"
    )
    assert none_request_id and none_request_id != all_request_id, (
        f"the two requests must have distinct request ids or the absence leg is meaningless: "
        f"ALL={all_request_id!r} NONE={none_request_id!r}"
    )

    delivered = _poll_until(
        lambda: _events_for(ctx, all_group, all_request_id),
        lambda events: any(e.get("logType") == "Tracing" for e in events)
        and any(e.get("logType") == "RequestSummary" for e in events),
        timeout_s=_budget_s(ctx, LOG_TIMEOUT_S), interval_s=1.0,
        description=(
            f"a Tracing AND a RequestSummary event for requestId {all_request_id} to be delivered "
            f"to {all_group}"
        ),
        ctx=ctx,
    )
    latency_s = time.monotonic() - t0

    summaries = [e for e in delivered if e.get("logType") == "RequestSummary"]
    assert len(summaries) == 1, (
        f"expected exactly one RequestSummary per request, got {len(summaries)}: {summaries!r}"
    )
    summary = summaries[0]
    assert summary.get("graphQLAPIId") == all_api, (
        f"RequestSummary named the wrong api: expected {all_api!r}, got "
        f"{summary.get('graphQLAPIId')!r}"
    )
    assert summary.get("statusCode") == all_status, (
        f"RequestSummary.statusCode must be the status the client observed: expected "
        f"{all_status}, got {summary.get('statusCode')!r}"
    )
    assert isinstance(summary.get("latency"), int) and summary["latency"] > 0, (
        f"RequestSummary.latency must be a positive nanosecond integer, got "
        f"{summary.get('latency')!r}"
    )

    tracings = [e for e in delivered if e.get("logType") == "Tracing"]
    probe_traces = [e for e in tracings if e.get("fieldName") == "probe"]
    assert len(probe_traces) == 1, (
        f"expected exactly one Tracing event for the single resolved field, got "
        f"{len(probe_traces)} of {len(tracings)} Tracing events: {tracings!r}"
    )
    trace = probe_traces[0]
    assert trace.get("parentType") == "Query", (
        f"Tracing.parentType must match the SDL: expected 'Query', got {trace.get('parentType')!r}"
    )
    assert trace.get("returnType") == "String", (
        f"Tracing.returnType must match the SDL: expected 'String', got "
        f"{trace.get('returnType')!r}"
    )
    assert trace.get("path") == ["probe"], (
        f"Tracing.path must be the response path of the resolved field: expected ['probe'], got "
        f"{trace.get('path')!r}"
    )
    assert isinstance(trace.get("duration"), int) and trace["duration"] > 0, (
        f"Tracing.duration must be a positive nanosecond integer, got {trace.get('duration')!r}"
    )
    assert isinstance(trace.get("startOffset"), int), (
        f"Tracing.startOffset must be a nanosecond integer offset, got "
        f"{trace.get('startOffset')!r}"
    )
    # Both spell apis/<id>/types/Query/resolvers/probe, not the .../fields/probe shape the
    # monitoring guide's prose implies.
    logged_arn = str(trace.get("resolverArn") or "")
    assert logged_arn == all_resolver_arn, (
        f"Tracing.resolverArn must be byte-identical to the resolverArn CreateResolver reported "
        f"for Query.probe: CreateResolver said {all_resolver_arn!r}, the log said {logged_arn!r}"
    )

    # The absence window is a fixed hold that starts once the twin ALL request's Tracing event has
    # arrived. Only Tracing is asserted absent: RequestSummary is request-level and may still be
    # emitted at NONE.
    hold = _ABSENCE_HOLD_S
    sample_interval_s = hold / 3.0
    deadline = time.monotonic() + hold
    samples = 0
    while time.monotonic() < deadline or samples < 3:
        quiet = _events_for(ctx, none_group, none_request_id)
        quiet_tracings = [e for e in quiet if e.get("logType") == "Tracing"]
        assert not quiet_tracings, (
            f"fieldLogLevel NONE must capture NO field-level logs, yet {len(quiet_tracings)} "
            f"Tracing event(s) arrived for requestId {none_request_id} in {none_group} after "
            f"{samples} sample(s); delivery on this wiring is demonstrably current because the "
            f"ALL api's Tracing event arrived in {latency_s:.1f}s and this absence is held for "
            f"{hold:.1f}s: {quiet!r}"
        )
        samples += 1
        time.sleep(sample_interval_s)
    assert samples >= 3, f"the absence window took too few samples to be meaningful: {samples}"

    # No Tracing event under any request id either, in case one was logged under another id.
    any_tracing = _all_tracing_log_types(ctx, none_group)
    assert not any_tracing, (
        f"fieldLogLevel NONE produced field-level Tracing events in {none_group} for some other "
        f"request: {any_tracing!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
