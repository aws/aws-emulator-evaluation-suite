"""appsync-batch-invoke-partial-item-error-isolates-the-failing-sibling."""
from __future__ import annotations

# AWS behavior this check relies on: in a BatchInvoke response, the documented per-element
# envelope is {"data": ..., "errorMessage": ..., "errorType": ...} (tutorial-lambda-resolvers.html,
# "Returning individual errors"). When exactly ONE element of the N-item array carries a non-null
# errorMessage/errorType, AppSync raises exactly one GraphQL error for that element's own field
# while every sibling element still resolves its "data" normally -- a per-item failure in a
# BatchInvoke response does not fail the other elements in the same invocation.

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-batch-invoke-partial-item-error-isolates-the-failing-sibling"
GROUP = "error-propagation"
SERVICES = ["appsync", "lambda"]

FANOUT = 5
MAX_BATCH_SIZE = 10
FAIL_INDEX = 2

SDL = """schema { query: Query }
type Detail {
    forId: ID!
}
type Post {
    id: ID!
    detail: Detail
}
type Query {
    posts(ids: [ID!]!): [Post]
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

# Query.posts is resolved locally: it turns the argument list into N parent Posts with no backend
# call, so the ONLY Lambda traffic is the N sibling Post.detail resolutions in one BatchInvoke.
JS_FANOUT = """import { runtime } from '@aws-appsync/utils';

export function request(ctx) {
  runtime.earlyReturn(ctx.args.ids.map((id) => ({ id })));
  return {};
}

export function response(ctx) {
  return ctx.result;
}
"""

JS_BATCH_INVOKE = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'BatchInvoke',
    payload: { forId: ctx.source.id },
  };
}

export function response(ctx) {
  if (ctx.result.errorMessage) {
    util.error(ctx.result.errorMessage, ctx.result.errorType);
  }
  return ctx.result.data;
}
"""

# One designated id in the batch gets a per-element error with a unique message/type; every other
# id gets ordinary data. The handler holds no assertion -- every assertion is in run().
BATCH_SRC = '''import json


def handler(event, context):
    fail_for = json.loads(%r)
    out = []
    for item in event:
        payload = item.get("payload") if isinstance(item, dict) and "payload" in item else item
        for_id = (payload or {}).get("forId")
        if for_id == fail_for["id"]:
            out.append({
                "data": None,
                "errorMessage": fail_for["message"],
                "errorType": fail_for["errorType"],
            })
        else:
            out.append({"data": {"forId": for_id}, "errorMessage": None, "errorType": None})
    return out
'''


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


def _poll_until(ctx, probe, predicate, *, cap_s=180.0, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    timeout_s = _budget_s(ctx, cap_s)
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
        raise AssertionError(
            f"the GraphQL endpoint {url!r} did not answer: {exc!r}"
        ) from exc
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", source)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


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
    role_name = ctx.unique_name(f"sim2real-behav-appsync-pbi-{label}-")
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


def _reap_log_group(ctx, group, *, reads: int = 3, interval_s: float = 2.0, cap_s: float = 180.0) -> None:
    """Delete log group ``group`` until ``reads`` consecutive reads find it absent.

    Raises if it is still coming back when the budget runs out: declare it in
    cleanup.leftovers rather than pretend it converged.
    """
    logs = ctx.client("logs")
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if any(g["logGroupName"] == group for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {group} still present after {timeout_s:.0f}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


def _create_function(ctx, source, role_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-appsync-pbi-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    created = _poll_until(
        ctx,
        lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=15, Publish=False,
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        cap_s=180.0, interval_s=2.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    state = _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        cap_s=180.0, interval_s=2.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    assert state["State"] == "Active", (
        f"the function did not become Active: {state.get('State')!r} {state.get('StateReason')!r}"
    )
    return name, created["FunctionArn"]


def _graphql_api(ctx, svc, sdl):
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-pbi-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(_teardown(lambda: svc.delete_graphql_api(apiId=api_id), "NotFoundException"))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        ctx,
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        cap_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: got {status['status']!r} {status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav pbi key")["apiKey"]["id"]
    ctx.on_cleanup(_teardown(lambda: svc.delete_api_key(apiId=api_id, id=key), "NotFoundException"))
    return api_id, uri, key


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """One element of a BatchInvoke response carrying errorMessage/errorType maps to exactly one
    GraphQL error scoped to that element's field, while every sibling element's data still
    resolves -- a per-item BatchInvoke failure does not fail the batch.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/tutorial-lambda-resolvers.html
    """
    svc = ctx.client("appsync")
    ids = [ctx.unique_name(f"post{i}-") for i in range(FANOUT)]
    fail_for = {
        "id": ids[FAIL_INDEX],
        "message": ctx.unique_name("boom-"),
        "errorType": "sim2real.PartialBatchItemError",
    }

    _exec_role, exec_arn = _create_role(ctx, "lambda.amazonaws.com", "exec")
    _fn_name, fn_arn = _create_function(ctx, BATCH_SRC % json.dumps(fail_for), exec_arn)

    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_role, ds_arn = _create_role(ctx, "appsync.amazonaws.com", "ds", inline_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
                       "Resource": [fn_arn, fn_arn + ":*"]}],
    })
    lambda_ds = _alnum(ctx, "batchfn")
    _poll_until(
        ctx,
        lambda: _try(svc.create_data_source, apiId=api_id, name=lambda_ds, type="AWS_LAMBDA",
                     serviceRoleArn=ds_arn, lambdaConfig={"lambdaFunctionArn": fn_arn}),
        lambda outcome: isinstance(outcome, dict),
        cap_s=180.0, interval_s=2.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(_teardown(
        lambda: svc.delete_data_source(apiId=api_id, name=lambda_ds), "NotFoundException"))

    none_ds = _alnum(ctx, "local")
    svc.create_data_source(apiId=api_id, name=none_ds, type="NONE")
    ctx.on_cleanup(_teardown(
        lambda: svc.delete_data_source(apiId=api_id, name=none_ds), "NotFoundException"))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="posts", kind="UNIT",
        dataSourceName=none_ds, runtime=APPSYNC_JS, code=JS_FANOUT,
    )
    ctx.on_cleanup(_teardown(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="posts"),
        "NotFoundException"))

    batched = svc.create_resolver(
        apiId=api_id, typeName="Post", fieldName="detail", kind="UNIT",
        dataSourceName=lambda_ds, runtime=APPSYNC_JS, code=JS_BATCH_INVOKE,
        maxBatchSize=MAX_BATCH_SIZE,
    )["resolver"]
    ctx.on_cleanup(_teardown(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Post", fieldName="detail"),
        "NotFoundException"))
    assert batched.get("maxBatchSize") == MAX_BATCH_SIZE, (
        f"CreateResolver did not retain maxBatchSize: expected {MAX_BATCH_SIZE}, got "
        f"{batched.get('maxBatchSize')!r}"
    )

    document = "query Batched($ids: [ID!]!) { posts(ids: $ids) { id detail { forId } } }"

    def _ask():
        return _post_json(ctx, url, {"x-api-key": key}, {"query": document, "variables": {"ids": ids}})

    def _is_propagation_error(status, body) -> bool:
        """A brand-new lambda:InvokeFunction grant propagates asynchronously: until it does,
        AppSync cannot invoke the function at all, so EVERY element errors (a Lambda access
        errorType) rather than just the one this check marked as failing."""
        if status != 200:
            return True
        return len(body.get("errors") or []) >= FANOUT

    # Poll only while the grant has not propagated yet; once it has, assert the real shape --
    # never let the poll predicate itself be the thing under test.
    status, body = _poll_until(
        ctx, _ask,
        lambda r: not _is_propagation_error(r[0], r[1]),
        cap_s=300.0, interval_s=2.0,
        description="the brand-new lambda:InvokeFunction grant to propagate",
    )
    assert status == 200, f"expected HTTP 200 even with a per-item error, got {status}: {body!r}"

    errors = body.get("errors") or []
    assert len(errors) == 1, f"expected exactly one GraphQL error, got {len(errors)}: {errors!r}"
    error = errors[0]
    assert error.get("message") == fail_for["message"], (
        f"error message: expected {fail_for['message']!r}, got {error.get('message')!r} from {error!r}"
    )
    assert error.get("errorType") == fail_for["errorType"], (
        f"error errorType: expected {fail_for['errorType']!r}, got {error.get('errorType')!r} "
        f"from {error!r}"
    )
    assert error.get("path") == ["posts", FAIL_INDEX, "detail"], (
        f"the error must be scoped to the one failing sibling's own field, expected "
        f"{['posts', FAIL_INDEX, 'detail']!r}, got {error.get('path')!r} from {error!r}"
    )

    posts = (body.get("data") or {}).get("posts") or []
    assert len(posts) == FANOUT, f"expected {FANOUT} posts, got {len(posts)}: {posts!r}"
    for i, (expected_id, post) in enumerate(zip(ids, posts)):
        assert post.get("id") == expected_id, f"post[{i}] id: got {post!r}"
        if i == FAIL_INDEX:
            assert post.get("detail") is None, (
                f"the failing sibling's own field must be null, got {post!r}"
            )
        else:
            assert post.get("detail") == {"forId": expected_id}, (
                f"sibling post[{i}] must still resolve its data despite the OTHER item's batch "
                f"error, got {post.get('detail')!r}"
            )

    # ---- positive control: a request with NO failing id must carry zero errors --------------
    control_ids = [ctx.unique_name(f"ctl{i}-") for i in range(FANOUT)]
    ctl_status, ctl_body = _post_json(
        ctx, url, {"x-api-key": key},
        {"query": document, "variables": {"ids": control_ids}},
    )
    assert ctl_status == 200 and not ctl_body.get("errors"), (
        f"a control batch with no failing id must carry zero errors: {ctl_status!r} {ctl_body!r}"
    )
    ctl_posts = (ctl_body.get("data") or {}).get("posts") or []
    assert len(ctl_posts) == FANOUT and all(p.get("detail") for p in ctl_posts), (
        f"the control batch must resolve every sibling's data: {ctl_posts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
