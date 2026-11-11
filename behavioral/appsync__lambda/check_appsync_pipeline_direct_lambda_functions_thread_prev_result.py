"""appsync-pipeline-direct-lambda-functions-thread-prev-result."""
from __future__ import annotations

# AWS behavior this check relies on: a PIPELINE resolver's Functions can each be a Direct Lambda
# function -- no request/response mapping template, no code -- and AppSync still threads
# ctx.prev.result from one function to the next: the SECOND function's event carries the FIRST
# function's return value under event["prev"]["result"], while event["arguments"],
# event["source"] and event["info"] stay the field's own values throughout the pipeline.
#
# Reference: https://aws.amazon.com/blogs/mobile/appsync-direct-lambda/

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-pipeline-direct-lambda-functions-thread-prev-result"
GROUP = "data-format"
SERVICES = ["appsync", "lambda"]

SDL = """schema { query: Query }
type Query {
    chain(msg: String!): String
}
"""

BEFORE_TEMPLATE = '{"version": "2018-05-29"}'
AFTER_TEMPLATE = "$util.toJson($context.result)"

# Stage 1: a Direct Lambda function with no template -- its whole return value becomes the
# pipeline's ctx.prev.result for stage 2. It holds no assertion; every assertion is in run().
STAGE1_SRC = """import json


def handler(event, context):
    return {"stage": 1, "echo": event["arguments"]["msg"]}
"""

# Stage 2: also a Direct Lambda function with no template. It echoes its WHOLE event back, so
# run() can inspect exactly what AppSync handed it, including ctx.prev.result from stage 1.
STAGE2_SRC = """import json


def handler(event, context):
    return json.dumps(event)
"""


# ===== helpers =====


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=40):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AssertionError(f"the GraphQL endpoint {url!r} did not answer: {exc!r}") from exc
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", source)
    return buf.getvalue()


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _teardown(undo, *not_found):
    """A cleanup running undo() where a failed delete raises, except on the resource's own
    not-found codes."""
    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "NoSuchEntity":
            raise RuntimeError(f"role {role_name} not deleted: {code}") from exc


def _create_role(ctx, trust_service, label, *, inline_policy=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-appsync-prev-{label}-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                             PolicyDocument=json.dumps(inline_policy))
    return role_name, arn


def _create_function(ctx, source, role_arn, label):
    # The execution role grants no logs:* permission (the claim here is prev.result threading,
    # not log reading), so the platform never creates /aws/lambda/<name>: nothing to reap.
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-appsync-prev-{label}-")
    created = _poll_until(
        ctx,
        lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=15, Publish=False,
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=_budget_s(ctx, 180.0),
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    state = _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=_budget_s(ctx, 180.0),
        description=f"Lambda {name} reaching a terminal State",
    )
    assert state["State"] == "Active", (
        f"the function did not become Active: {state.get('State')!r} {state.get('StateReason')!r}"
    )
    return name, created["FunctionArn"]


def _graphql_api(ctx, svc, sdl):
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-prev-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        ctx,
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=_budget_s(ctx, 180.0),
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: got {status['status']!r} {status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav prev key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


def _lambda_data_source(ctx, svc, api_id, role_arn, function_arn, label):
    ds_name = _alnum(ctx, f"ds_{label}_")
    _poll_until(
        ctx,
        lambda: _try(svc.create_data_source, apiId=api_id, name=ds_name, type="AWS_LAMBDA",
                     serviceRoleArn=role_arn, lambdaConfig={"lambdaFunctionArn": function_arn}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=_budget_s(ctx, 180.0),
        description=f"CreateDataSource {ds_name} to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    return ds_name


def _direct_function(ctx, svc, api_id, ds_name, label):
    """A pipeline Function on a Direct Lambda data source: no request/response templates."""
    fn = svc.create_function(
        apiId=api_id, name=_alnum(ctx, f"fn_{label}_"), dataSourceName=ds_name,
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    ctx.on_cleanup(lambda: svc.delete_function(apiId=api_id, functionId=fn["functionId"]))
    assert not fn.get("requestMappingTemplate") and not fn.get("code"), (
        f"the pipeline Function must be a Direct Lambda function (no template, no code): {fn!r}"
    )
    return fn["functionId"]


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PIPELINE resolver's second Direct Lambda function receives the first function's return
    value as event["prev"]["result"], while its own arguments/source/info stay the field's own.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/direct-lambda-reference.html
    """
    svc = ctx.client("appsync")
    _exec_role, exec_arn = _create_role(ctx, "lambda.amazonaws.com", "exec")
    stage1_name, stage1_arn = _create_function(ctx, STAGE1_SRC, exec_arn, "stage1")
    stage2_name, stage2_arn = _create_function(ctx, STAGE2_SRC, exec_arn, "stage2")

    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_role, ds_arn = _create_role(ctx, "appsync.amazonaws.com", "ds", inline_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
                       "Resource": [stage1_arn, stage1_arn + ":*",
                                    stage2_arn, stage2_arn + ":*"]}],
    })
    ds1 = _lambda_data_source(ctx, svc, api_id, ds_arn, stage1_arn, "stage1")
    ds2 = _lambda_data_source(ctx, svc, api_id, ds_arn, stage2_arn, "stage2")

    fn1_id = _direct_function(ctx, svc, api_id, ds1, "stage1")
    fn2_id = _direct_function(ctx, svc, api_id, ds2, "stage2")

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="chain", kind="PIPELINE",
        requestMappingTemplate=BEFORE_TEMPLATE, responseMappingTemplate=AFTER_TEMPLATE,
        pipelineConfig={"functions": [fn1_id, fn2_id]},
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="chain"))

    query = "query Chain($m: String!) { chain(msg: $m) }"
    marker = ctx.unique_name("prev-")

    def _ask():
        return _post_json(ctx, url, {"x-api-key": key},
                          {"query": query, "variables": {"m": marker}})

    # Two fresh lambda:InvokeFunction grants propagate asynchronously -- poll for a response that
    # actually parses as the stage-2 echo, not just a 200.
    status, body = _poll_until(
        ctx,
        _ask,
        lambda r: r[0] == 200 and not r[1].get("errors") and (r[1].get("data") or {}).get("chain"),
        timeout_s=_budget_s(ctx, 300.0),
        description="both pipeline functions to settle and the resolver to resolve",
    )
    assert status == 200, f"expected HTTP 200, got {status}: {body!r}"
    assert not body.get("errors"), f"the pipeline resolver returned errors: {body['errors']!r}"

    stage2_event = json.loads(body["data"]["chain"])

    # ---- the second function's event carries the first function's return as prev.result ------
    assert stage2_event.get("prev") == {"result": {"stage": 1, "echo": marker}}, (
        f"stage 2 must receive stage 1's return value as prev.result: got "
        f"{stage2_event.get('prev')!r}"
    )

    # ---- and the field's own values are unchanged through the pipeline -----------------------
    assert stage2_event.get("arguments") == {"msg": marker}, (
        f"stage 2 arguments must still be the field's own: got {stage2_event.get('arguments')!r}"
    )
    assert stage2_event.get("source") is None, (
        f"a root field's source must still be null at stage 2: got {stage2_event.get('source')!r}"
    )
    info = stage2_event.get("info") or {}
    assert info.get("fieldName") == "chain" and info.get("parentTypeName") == "Query", (
        f"stage 2 info must still name Query.chain: got {info!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
