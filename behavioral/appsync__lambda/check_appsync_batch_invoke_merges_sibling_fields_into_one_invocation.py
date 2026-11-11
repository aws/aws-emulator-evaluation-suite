"""appsync-batch-invoke-merges-sibling-fields-into-one-invocation."""
from __future__ import annotations

# H1  with ``operation: 'BatchInvoke'`` and maxBatchSize >= N, AppSync merges the N sibling
#     ``Post.detail`` resolutions into exactly ONE Lambda invocation whose event is a BARE list of
#     N merged payloads (not a mapping document) -- documented in the JS resolver batching guide.
# H2  the Lambda must return a list of N results in the SAME ORDER as the request items, and
#     AppSync maps element i onto sibling i. Documented; asserted by having each element echo the
#     parent id it was computed from.
# H3  batching happens per FIELD per request, so a single GraphQL request over N parents is one
#     invocation -- not N, and not one per maxBatchSize chunk when N <= maxBatchSize.
# H4  ``{"data": ..., "errorMessage": null, "errorType": null}`` per element is the documented
#     batch result envelope, and a null errorType leaves the field unerrored.

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-batch-invoke-merges-sibling-fields-into-one-invocation"
GROUP = "server-side"
SERVICES = ["appsync", "lambda"]

FANOUT = 5
MAX_BATCH_SIZE = 10

SDL = """schema { query: Query }
type Detail {
    forId: ID!
    batchLen: Int!
}
type Post {
    id: ID!
    detail: Detail
}
type Query {
    posts(ids: [ID!]!): [Post]
}
"""

# Query.posts is resolved locally: it turns the argument list into N parent Posts with no backend
# call at all, so the ONLY Lambda traffic in the check is the N sibling Post.detail resolutions.
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
    util.error(ctx.result.errorMessage, ctx.result.errorType, ctx.result.data);
  }
  return ctx.result.data;
}
"""

# The handler reports what it SAW -- the container type and the number of items -- on an
# independent side-channel, and answers with one result per item echoing the id it came from. It
# branches on the event shape only to READ it; every assertion lives in the check body.
BATCH_SRC = '''import json
import os

import boto3

_sqs = boto3.client("sqs")


def _items(event):
    if isinstance(event, list):
        return "list", event
    if isinstance(event, dict) and isinstance(event.get("payload"), list):
        return "document", event["payload"]
    return "single", [event]


def handler(event, context):
    kind, items = _items(event)
    out = []
    for item in items:
        payload = item.get("payload") if isinstance(item, dict) and "payload" in item else item
        for_id = (payload or {}).get("forId")
        out.append({
            "data": {"forId": for_id, "batchLen": len(items)},
            "errorMessage": None,
            "errorType": None,
        })
    _sqs.send_message(
        QueueUrl=os.environ["SIM2REAL_QUEUE_URL"],
        MessageBody=json.dumps({
            "kind": kind,
            "n": len(items),
            "forIds": [o["data"]["forId"] for o in out],
            "requestId": context.aws_request_id,
        }),
    )
    return out
'''

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


# ===== helpers =====


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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
        return None, {"transport_error": str(exc)}
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
    """The call's result, or the AWS error code -- never a bare False, so a poll timeout names
    the code that kept it from settling."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


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


def _create_role(ctx, trust_service, *, inline_policy=None, managed_policies=()):
    """An IAM role trusted by ``trust_service``, with its teardown registered.

    IAM exposes no condition reporting that a trust policy is effective, so each first use retries.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-batch-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return arn


def _create_queue(ctx):
    """A side-channel queue. VisibilityTimeout 0 looks deterministic but is not: with the message
    never hiding, a single ReceiveMessage call can hand back the SAME undeleted message more than
    once before the delete registers -- confirmed in this check by ten drained reports sharing one
    identical Lambda ``aws_request_id``, which is only possible from one physical invocation. A
    non-zero timeout, held past the delete this check issues immediately after every receive,
    removes the window."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-appsync-batch-")
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"VisibilityTimeout": "30", "MessageRetentionPeriod": "3600"},
        tags={t["Key"]: t["Value"] for t in _tags_kv()},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    return url, arn


def _drain(ctx, queue_url, *, rounds=3):
    """Receive and DELETE every currently visible message; return the parsed bodies."""
    sqs = ctx.client("sqs")
    bodies = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=30
        )
        messages = resp.get("Messages") or []
        for message in messages:
            try:
                bodies.append(json.loads(message["Body"]))
            except ValueError:
                bodies.append({"kind": "__unparsed__", "raw": message["Body"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        if not messages:
            break
    return bodies


def _visible_count(ctx, queue_url):
    """The queue's own message count -- the SECOND independent observable behind the "no second
    invocation" assertion."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (
        int(attrs["ApproximateNumberOfMessages"])
        + int(attrs.get("ApproximateNumberOfMessagesNotVisible", "0"))
    )


def _create_function(ctx, source, role_arn, env):
    """A python Lambda, its teardown, its service-created log group's teardown, and a wait for
    Active. Creation is retried because a brand-new role is not yet assumable."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-appsync-batch-fn-")
    created = _poll_until(
        lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=30, Publish=False,
            Environment={"Variables": env},
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    ctx.on_cleanup(lambda: _delete_log_group_when_it_exists(ctx, f"/aws/lambda/{name}"))
    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=180.0, interval_s=3.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    assert state["State"] == "Active", (
        f"the batch function did not become Active: {state.get('State')!r} "
        f"{state.get('StateReason')!r}"
    )
    return name, created["FunctionArn"]


def _delete_log_group_when_it_exists(ctx, group, timeout_s=90.0):
    """Delete a SERVICE-created log group, waiting for it to appear first, and never raise --
    an un-waited delete leaks silently while the check still reports PASS."""
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
            time.sleep(3.0)


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: expected SUCCESS/ACTIVE, got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav batch key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """BatchInvoke with maxBatchSize resolves N sibling fields in ONE Lambda invocation carrying a
    list of N payloads, and AppSync maps result i back onto sibling i.
    """
    svc = ctx.client("appsync")

    queue_url, queue_arn = _create_queue(ctx)
    exec_role = _create_role(
        ctx, "lambda.amazonaws.com",
        managed_policies=("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",),
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sqs:SendMessage"],
                           "Resource": [queue_arn]}],
        },
    )
    _fn_name, fn_arn = _create_function(
        ctx, BATCH_SRC, exec_role, {"SIM2REAL_QUEUE_URL": queue_url}
    )

    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_role = _create_role(ctx, "appsync.amazonaws.com", inline_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
                       "Resource": [fn_arn, fn_arn + ":*"]}],
    })
    lambda_ds = _alnum(ctx, "batchfn")
    _poll_until(
        lambda: _try(svc.create_data_source, apiId=api_id, name=lambda_ds, type="AWS_LAMBDA",
                     serviceRoleArn=ds_role,
                     lambdaConfig={"lambdaFunctionArn": fn_arn}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=lambda_ds))

    none_ds = _alnum(ctx, "local")
    svc.create_data_source(apiId=api_id, name=none_ds, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=none_ds))

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="posts", kind="UNIT",
        dataSourceName=none_ds, runtime=APPSYNC_JS, code=JS_FANOUT,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="posts"))

    batched = svc.create_resolver(
        apiId=api_id, typeName="Post", fieldName="detail", kind="UNIT",
        dataSourceName=lambda_ds, runtime=APPSYNC_JS, code=JS_BATCH_INVOKE,
        maxBatchSize=MAX_BATCH_SIZE,
    )["resolver"]
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Post", fieldName="detail"))
    assert batched.get("maxBatchSize") == MAX_BATCH_SIZE, (
        f"CreateResolver did not retain maxBatchSize, so nothing below tests batching: expected "
        f"{MAX_BATCH_SIZE}, got {batched.get('maxBatchSize')!r}"
    )

    ids = [ctx.unique_name(f"post{i}-") for i in range(FANOUT)]
    document = (
        "query Batched($ids: [ID!]!) { posts(ids: $ids) { id detail { forId batchLen } } }"
    )

    def _ask(post_ids=ids):
        return _post_json(ctx, url, {"x-api-key": key},
                          {"query": document, "variables": {"ids": post_ids}})

    # ---- barrier FIRST: prove the whole path works before any count is taken -----------------
    # A brand-new lambda:InvokeFunction grant is still propagating for a while, and during that
    # window the field resolves null with an error -- which would otherwise read as "AppSync
    # batched into zero invocations".
    _poll_until(
        _ask,
        lambda res: res[0] == 200 and not res[1].get("errors")
        and len((res[1].get("data") or {}).get("posts") or []) == FANOUT
        and all((p or {}).get("detail") for p in res[1]["data"]["posts"]),
        timeout_s=300.0, interval_s=5.0,
        description="the batched Lambda resolver to resolve every sibling on the live endpoint",
    )
    warm = _poll_until(
        lambda: _drain(ctx, queue_url),
        lambda bodies: bool(bodies),
        timeout_s=180.0, interval_s=5.0,
        description="the side-channel to deliver the warm-up invocation report",
    )
    assert warm, (
        "the side-channel delivered nothing for the warm-up, so no count asserted below would mean "
        "anything"
    )
    _drain(ctx, queue_url)  # leave the queue empty before the measured request

    # ---- the measured request ----------------------------------------------------------------
    status, body = _ask()
    assert status == 200, f"the measured request did not return 200: {status!r} {body!r}"
    assert not body.get("errors"), f"the measured request returned errors: {body['errors']!r}"

    reports = _poll_until(
        lambda: _drain(ctx, queue_url),
        lambda bodies: bool(bodies),
        timeout_s=180.0, interval_s=5.0,
        description="the invocation report for the measured request",
    )
    assert len(reports) == 1, (
        f"{FANOUT} sibling field resolutions with maxBatchSize={MAX_BATCH_SIZE} must produce "
        f"exactly ONE Lambda invocation, got {len(reports)}: {reports!r}"
    )
    report = reports[0]
    assert report.get("n") == FANOUT, (
        f"the single invocation must carry all {FANOUT} merged payloads; the Lambda reports it saw "
        f"{report.get('n')!r} item(s) as a {report.get('kind')!r}: {report!r}"
    )
    assert report.get("kind") == "list", (
        f"a BatchInvoke event must be a BARE list of the {FANOUT} merged payloads, never a mapping "
        f"document with a 'payload' key -- documented in the JS resolver batching guide; "
        f"the Lambda saw {report.get('kind')!r}: {report!r}"
    )

    # ---- no second invocation: a control request sent AFTER it must report first -----------
    ctl_ids = [ctx.unique_name(f"ctl{i}-") for i in range(FANOUT)]
    ctl_status, ctl_body = _ask(ctl_ids)
    assert ctl_status == 200 and not ctl_body.get("errors"), (
        f"the control request failed: {ctl_status!r} {ctl_body!r}"
    )
    after = []

    def _until_control():
        after.extend(_drain(ctx, queue_url))
        return after

    _poll_until(
        _until_control,
        lambda bodies: any(b.get("forIds") == ctl_ids for b in bodies),
        timeout_s=180.0, interval_s=2.0,
        description="the invocation report for the control request",
    )
    after.extend(_drain(ctx, queue_url))
    extra = [b for b in after if b.get("forIds") != ctl_ids]
    assert not extra, (
        f"AppSync must not invoke the Lambda again for the same request: {len(extra)} further "
        f"invocation report(s) arrived before or with the control request's report: {extra!r}"
    )
    still_queued = _visible_count(ctx, queue_url)
    assert still_queued == 0, (
        f"second observable: the queue must be empty after one batched invocation, got "
        f"{still_queued} message(s) visible or in flight"
    )

    # ---- the batch length and the ORDER both survive back out through GraphQL -----------------
    posts = body["data"]["posts"]
    assert len(posts) == FANOUT, (
        f"expected {FANOUT} posts back, got {len(posts)}: {posts!r}"
    )
    for expected_id, post in zip(ids, posts):
        assert post["id"] == expected_id, (
            f"the parent list lost its order: expected {expected_id!r}, got {post['id']!r} in "
            f"{posts!r}"
        )
        detail = post["detail"]
        assert detail["forId"] == expected_id, (
            f"AppSync mapped batch result onto the wrong sibling: post {expected_id!r} got a "
            f"detail computed for {detail['forId']!r} -- the Lambda returns results in request "
            f"order, so element i must land on sibling i: {posts!r}"
        )
        assert detail["batchLen"] == FANOUT, (
            f"the Lambda saw a batch of {detail['batchLen']} while resolving {expected_id!r}; with "
            f"maxBatchSize={MAX_BATCH_SIZE} all {FANOUT} siblings must share one batch: {posts!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
