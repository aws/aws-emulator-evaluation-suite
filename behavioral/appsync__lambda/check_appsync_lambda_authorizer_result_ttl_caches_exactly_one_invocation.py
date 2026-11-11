"""appsync-lambda-authorizer-result-ttl-caches-exactly-one-invocation."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-lambda-authorizer-result-ttl-caches-exactly-one-invocation"
GROUP = "server-side"
SERVICES = ["appsync", "lambda"]

AUTH_TTL_S = 300
SDL = """schema { query: Query }
type Query {
    whoami: String
}
"""

# The authorizer records every invocation on an SQS side-channel before answering, because
# AppSync's own API never reports how often it called the authorizer.
AUTHORIZER_SRC = '''import json
import os

import boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    token = (event or {}).get("authorizationToken") or ""
    _sqs.send_message(
        QueueUrl=os.environ["SIM2REAL_QUEUE_URL"],
        MessageBody=json.dumps({"token": token, "requestId": context.aws_request_id}),
    )
    return {"isAuthorized": True, "resolverContext": {"token": token}}
'''

JS_ECHO_IDENTITY = """import { runtime } from '@aws-appsync/utils';

export function request(ctx) {
  runtime.earlyReturn(ctx.identity.resolverContext.token);
  return {};
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


# ===== local helpers =====


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(ctx, probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    """Bounded retry that raises on timeout rather than returning its last value."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
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

    IAM reports no condition for a trust policy becoming effective; callers retry at first use.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-authz-role-")
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
    """The side-channel queue, with VisibilityTimeout 0."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-appsync-authz-")
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"VisibilityTimeout": "0", "MessageRetentionPeriod": "3600"},
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
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
            VisibilityTimeout=0,
        )
        messages = resp.get("Messages") or []
        for message in messages:
            try:
                bodies.append(json.loads(message["Body"]))
            except ValueError:
                bodies.append({"token": None, "raw": message["Body"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        if not messages:
            break
    return bodies


def _invocations(bodies, token):
    """Distinct Lambda invocations naming ``token``, deduped by requestId.

    With VisibilityTimeout=0 one ReceiveMessage can return the same message several times, so the
    raw message count is not the invocation count.
    """
    seen = {}
    for b in bodies:
        if b.get("token") == token:
            seen[b.get("requestId")] = b
    return list(seen.values())


def _visible_count(ctx, queue_url):
    """Visible plus in-flight messages: a second observable behind the absence assertion."""
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
    name = ctx.unique_name("sim2real-behav-appsync-authz-fn-")
    created = _poll_until(
        ctx, lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=20, Publish=False,
            Environment={"Variables": env},
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=2.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    ctx.on_cleanup(lambda: _delete_log_group_when_it_exists(ctx, f"/aws/lambda/{name}"))
    state = _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=180.0, interval_s=2.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    assert state["State"] == "Active", (
        f"the authorizer function did not become Active: {state.get('State')!r} "
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


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, graphql_uri, api_arn)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        ctx, lambda: svc.get_schema_creation_status(apiId=api_id),
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
    return api_id, uri, api["arn"]


# ===== end local helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """authorizerResultTtlInSeconds caches the authorizer result per token: 1 invocation cold,
    0 on the repeat, 1 for a different token, counted on an SQS side-channel the authorizer writes.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
    """
    svc = ctx.client("appsync")
    lam = ctx.client("lambda")

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
    authorizer_name, authorizer_arn = _create_function(
        ctx, AUTHORIZER_SRC, exec_role, {"SIM2REAL_QUEUE_URL": queue_url}
    )

    api_id, url, api_arn = _graphql_api(
        ctx, svc, SDL,
        authenticationType="AWS_LAMBDA",
        lambdaAuthorizerConfig={
            "authorizerUri": authorizer_arn,
            "authorizerResultTtlInSeconds": AUTH_TTL_S,
        },
    )
    stored = svc.get_graphql_api(apiId=api_id)["graphqlApi"].get("lambdaAuthorizerConfig") or {}
    assert stored.get("authorizerResultTtlInSeconds") == AUTH_TTL_S, (
        f"the api did not retain the authorizer TTL under test: expected {AUTH_TTL_S}, got "
        f"{stored.get('authorizerResultTtlInSeconds')!r}"
    )

    lam.add_permission(
        FunctionName=authorizer_name, StatementId="sim2real-appsync-authorizer",
        Action="lambda:InvokeFunction", Principal="appsync.amazonaws.com", SourceArn=api_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(
        FunctionName=authorizer_name, StatementId="sim2real-appsync-authorizer"
    ))

    ds_name = _alnum(ctx, "none")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="whoami", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_ECHO_IDENTITY,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="whoami"))

    document = "query Who { whoami }"

    def _ask(token):
        return _post_json(ctx, url, {"Authorization": token}, {"query": document})

    warm_token = ctx.unique_name("warm-")
    cold_token = ctx.unique_name("cold-")
    other_token = ctx.unique_name("other-")

    # Barrier: AppSync answers 401 while lambda:InvokeFunction for appsync is still propagating,
    # so an authorized success, and its side-channel message, must come before anything is counted.
    _status, warm = _poll_until(
        ctx, lambda: _ask(warm_token),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=300.0, interval_s=2.0,
        description="the Lambda authorizer to become invocable and authorize a request",
    )
    assert (warm.get("data") or {}).get("whoami") == warm_token, (
        f"the authorizer's resolverContext did not reach ctx.identity inside the resolver: "
        f"expected {warm_token!r}, got {warm!r}"
    )
    drained = _poll_until(
        ctx, lambda: _drain(ctx, queue_url),
        lambda bodies: any(b.get("token") == warm_token for b in bodies),
        timeout_s=180.0, interval_s=2.0,
        description="the side-channel to deliver the warm-up authorizer invocation",
    )
    assert drained, (
        "the side-channel delivered nothing for the warm-up, so no zero asserted below would mean "
        "anything"
    )
    _drain(ctx, queue_url)  # leave the queue empty before the counted legs

    # COLD: a fresh token invokes the authorizer exactly once.
    cold_status, cold_body = _ask(cold_token)
    assert cold_status == 200 and not cold_body.get("errors"), (
        f"the cold-token request failed: {cold_status!r} {cold_body!r}"
    )
    cold_messages = _poll_until(
        ctx, lambda: _drain(ctx, queue_url),
        lambda bodies: any(b.get("token") == cold_token for b in bodies),
        timeout_s=180.0, interval_s=2.0,
        description=f"the authorizer invocation for the cold token {cold_token}",
    )
    cold_hits = _invocations(cold_messages, cold_token)
    assert len(cold_hits) == 1, (
        f"a cold token must invoke the authorizer exactly once, got {len(cold_hits)} distinct "
        f"invocation(s) (by requestId) across {len(cold_messages)} message(s): {cold_messages!r}"
    )

    # CACHED: the identical request must not invoke the authorizer again.
    repeat_status, repeat_body = _ask(cold_token)
    assert repeat_status == 200 and not repeat_body.get("errors"), (
        f"the repeated request must still be authorized -- from cache: {repeat_status!r} "
        f"{repeat_body!r}"
    )
    assert (repeat_body.get("data") or {}).get("whoami") == cold_token, (
        f"the cached authorizer result must still carry the resolverContext: expected "
        f"{cold_token!r}, got {repeat_body!r}"
    )

    # MISS, ordered after the repeat: a different token re-proves delivery is live, and nothing
    # drained up to its invocation may be a re-invocation for the cached token.
    other_status, other_body = _ask(other_token)
    assert other_status == 200 and not other_body.get("errors"), (
        f"the different-token request failed: {other_status!r} {other_body!r}"
    )
    assert (other_body.get("data") or {}).get("whoami") == other_token, (
        f"a cache MISS must run the authorizer and carry the NEW token's resolverContext: expected "
        f"{other_token!r}, got {other_body!r}"
    )
    collected: list = []

    def _drain_until_other():
        collected.extend(_drain(ctx, queue_url))
        return collected

    _poll_until(
        ctx, _drain_until_other,
        lambda bodies: any(b.get("token") == other_token for b in bodies),
        timeout_s=180.0, interval_s=2.0,
        description=(
            f"the authorizer invocation for the different token {other_token} -- the repair leg "
            f"that proves the side-channel is still live"
        ),
    )
    other_hits = _invocations(collected, other_token)
    assert len(other_hits) == 1, (
        f"a different token is a cache MISS and must invoke the authorizer exactly once, got "
        f"{len(other_hits)} distinct invocation(s) (by requestId) across {len(collected)} "
        f"message(s): {collected!r}"
    )
    repeat_hits = [b for b in collected if b.get("token") == cold_token]
    assert not repeat_hits, (
        f"authorizerResultTtlInSeconds={AUTH_TTL_S} must serve the repeated request from cache, "
        f"yet the authorizer was invoked {len(repeat_hits)} more time(s) for {cold_token!r} before "
        f"the different token's invocation arrived: {collected!r}"
    )
    still_queued = _visible_count(ctx, queue_url)
    assert still_queued == 0, (
        f"second observable: the queue must be empty after a cached authorization, got "
        f"{still_queued} message(s) visible or in flight"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
