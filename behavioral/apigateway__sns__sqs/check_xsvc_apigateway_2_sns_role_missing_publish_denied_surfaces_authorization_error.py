"""xsvc-apigateway-2-sns-role-missing-publish-denied-surfaces-authorization-error."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-2-sns-role-missing-publish-denied-surfaces-authorization-error"
GROUP = "permission-chain"
SERVICES = ["apigateway", "sns", "sqs"]

_REQUEST_TEMPLATE = (
    "Action=Publish&TopicArn=$util.urlEncode('__TOPIC__')"
    "&Message=$util.urlEncode($input.body)"
    "&MessageAttributes.entry.1.Name=route"
    "&MessageAttributes.entry.1.Value.DataType=String"
    "&MessageAttributes.entry.1.Value.StringValue=$util.urlEncode($context.resourcePath)"
)
_OK_TEMPLATE = (
    '{"published": true, '
    '"messageId": "$input.path(\'$.PublishResponse.PublishResult.MessageId\')"}'
)
_ERR_TEMPLATE = (
    '{"published": false, "surfacedCode": "$input.path(\'$.Error.Code\')", '
    '"surfacedType": "$input.path(\'$.Error.Type\')", '
    '"surfacedMessage": $input.json(\'$.Error.Message\')}'
)


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An SNS Publish integration whose role lacks sns:Publish surfaces AuthorizationError as a 403
    and delivers nothing, while a granted twin route delivers; granting the action repairs it.
    """
    sns = ctx.client("sns")
    iam = ctx.client("iam")
    topic_arn = sns.create_topic(Name=_xname(ctx, "apigw2-topic"),
                                 Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))
    queue = _create_subscribed_queue(ctx, topic_arn, "sub", raw=True)

    granted = _create_role(ctx, "apigateway.amazonaws.com",
                           inline_policy=_allow(["sns:Publish"], topic_arn))
    # The denied role holds a different SNS action, so only sns:Publish is missing.
    denied = _create_role(ctx, "apigateway.amazonaws.com",
                          inline_policy=_allow(["sns:GetTopicAttributes"], topic_arn))

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw2-snsdeny")
    for path, role in (("granted", granted), ("denied", denied)):
        rid = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart=path)["id"]
        ag.put_method(restApiId=api_id, resourceId=rid, httpMethod="POST",
                      authorizationType="NONE")
        ag.put_integration(
            restApiId=api_id, resourceId=rid, httpMethod="POST", type="AWS",
            integrationHttpMethod="POST", uri=f"arn:aws:apigateway:{ctx.region}:sns:path//",
            credentials=role["arn"], passthroughBehavior="NEVER",
            requestParameters={
                "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"},
            requestTemplates={
                "application/json": _REQUEST_TEMPLATE.replace("__TOPIC__", topic_arn)},
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
    hdrs = {"Content-Type": "application/json"}
    tag = ctx.unique_name("m-")

    def body(kind):
        return json.dumps({"marker": f"{tag}-{kind}"}).encode()

    def routes(msgs):
        return sorted((m["MessageAttributes"]["route"]["StringValue"],
                       json.loads(m["Body"])["marker"]) for m in msgs)

    # Beat 1 - positive control through the granted twin, observed at the subscriber.
    _, _, t = _poll_http(url_ok, accept=lambda s, t: s == 200 and '"published": true' in t,
                         body=body("control"), headers=hdrs, description="granted twin route")
    got = _drain_until(ctx, queue, lambda ms: len(ms) >= 1)
    assert routes(got) == [("/granted", f"{tag}-control")], (
        f"subscriber received {routes(got)!r} for the granted control publish")

    # Beats 2+3 - the denied route, polled only past the role's assume-propagation window.
    st, _, t = _poll_http(url_no, accept=lambda s, t: s in (200, 403), body=body("denied"),
                          headers=hdrs, description="denied route")
    assert st == 403, f"role without sns:Publish was NOT refused: {st} {t[:300]!r}"
    err = json.loads(t)
    want = (f"User: {_assumed_role_arn(denied['arn'])}/{_APIGW_SESSION} is not authorized to "
            f"perform: SNS:Publish on resource: {topic_arn} because no identity-based policy "
            f"allows the SNS:Publish action")
    assert err == {"published": False, "surfacedCode": "AuthorizationError",
                   "surfacedType": "Sender", "surfacedMessage": want}, (
        f"SNS's refusal was not surfaced as AuthorizationError/Sender with {want!r}; got {err!r}")

    # Beat 4 - effect absent at the subscriber, bounded by a granted publish issued after it.
    st, _, t = _http("POST", url_ok, body=body("barrier"), headers=hdrs)
    assert st == 200, f"granted twin stopped publishing: {st} {t[:300]!r}"
    got = _drain_until(ctx, queue, lambda ms: any(f"{tag}-barrier" in m["Body"] for m in ms))
    assert routes(got) == [("/granted", f"{tag}-barrier")], (
        f"subscriber received {routes(got)!r}; the refused /denied publish must be absent")

    # Beats 5+6 - grant the one missing action; the identical route now reaches the subscriber.
    iam.put_role_policy(RoleName=denied["name"], PolicyName="inline", PolicyDocument=json.dumps(
        _allow(["sns:GetTopicAttributes", "sns:Publish"], topic_arn)))
    _poll_http(url_no, accept=lambda s, t: s == 200 and '"published": true' in t,
               body=body("repaired"), headers=hdrs, timeout_s=120.0,
               description="denied route after granting sns:Publish")
    got = _drain_until(ctx, queue, lambda ms: any(f"{tag}-repaired" in m["Body"] for m in ms))
    assert routes(got) == [("/denied", f"{tag}-repaired")], (
        f"after the grant the subscriber received {routes(got)!r}, expected exactly the "
        f"repaired /denied publish (and never the refused one)")


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-"), "sim2real": CHECK}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


# The session name API Gateway uses when it assumes an integration's credentials role.
_APIGW_SESSION = "BackplaneAssumeRoleSession"


def _assumed_role_arn(role_arn):
    """`arn:aws:iam::<acct>:role/<name>` -> `arn:aws:sts::<acct>:assumed-role/<name>`."""
    prefix, name = role_arn.split(":role/", 1)
    return prefix.replace(":iam::", ":sts::") + ":assumed-role/" + name.rsplit("/", 1)[-1]


def _error_code(fn) -> str:
    """The AWS error code fn() raised. RAISES if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
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


def _env(m):
    """The SNS JSON envelope carried in a non-raw SQS subscriber's Body."""
    return json.loads(m["Body"])


def _create_subscribed_queue(ctx, topic_arn, kind, *, raw, filter_policy=None):
    """A queue (teardown registered) whose policy admits only this topic, subscribed to it
    (unsubscribe registered). Returns the queue URL."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    url = sqs.create_queue(QueueName=_xname(ctx, f"apigw2-{kind}"),
                           tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
        "Action": "sqs:SendMessage", "Resource": arn,
        "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]}
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    attrs = {"RawMessageDelivery": "true" if raw else "false"}
    if filter_policy:
        attrs["FilterPolicy"] = json.dumps(filter_policy)
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn, Attributes=attrs,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub))
    return url


def _drain_until(ctx, queue_url, done, *, timeout_s=90.0):
    """Receive+delete until done(all_received) is true; return everything received, in order,
    so the caller can assert nothing unexpected arrived alongside."""
    sqs = ctx.client("sqs")
    got = []
    deadline = time.monotonic() + timeout_s
    while not done(got):
        if time.monotonic() > deadline:
            raise AssertionError(f"expected delivery never completed within {timeout_s}s; "
                                 f"received {[m['Body'][:200] for m in got]!r}")
        for m in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            got.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return got


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
