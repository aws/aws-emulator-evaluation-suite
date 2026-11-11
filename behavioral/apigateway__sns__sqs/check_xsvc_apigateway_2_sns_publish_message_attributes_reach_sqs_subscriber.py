"""xsvc-apigateway-2-sns-publish-message-attributes-reach-sqs-subscriber."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-2-sns-publish-message-attributes-reach-sqs-subscriber"
GROUP = "data-format"
SERVICES = ["apigateway", "sns", "sqs"]

# The client body becomes the SNS Message; a request HEADER and a body FIELD become two typed
# SNS message attributes (String and Number) through the Query MessageAttributes.entry.N form.
_REQUEST_TEMPLATE = (
    "Action=Publish&TopicArn=$util.urlEncode('__TOPIC__')"
    "&Message=$util.urlEncode($input.body)"
    "&MessageAttributes.entry.1.Name=color"
    "&MessageAttributes.entry.1.Value.DataType=String"
    "&MessageAttributes.entry.1.Value.StringValue=$util.urlEncode($input.params('x-color'))"
    "&MessageAttributes.entry.2.Name=qty"
    "&MessageAttributes.entry.2.Value.DataType=Number"
    "&MessageAttributes.entry.2.Value.StringValue=$input.path('$.qty')"
)
_RESPONSE_TEMPLATE = (
    '{"published": true, '
    '"messageId": "$input.path(\'$.PublishResponse.PublishResult.MessageId\')"}'
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An API Gateway SNS Publish integration maps a header and a body field to typed message
    attributes that reach an envelope subscriber as {Type, Value} and a raw subscriber as SQS
    attributes, and a filter policy on that header admits only matching publishes.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = sns.create_topic(Name=_xname(ctx, "apigw2-topic"),
                                 Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))
    color = ctx.unique_name("hue-")

    env_q = _create_subscribed_queue(ctx, topic_arn, "env", raw=False)
    raw_q = _create_subscribed_queue(ctx, topic_arn, "raw", raw=True,
                                     filter_policy={"color": [color]})

    role = _create_role(ctx, "apigateway.amazonaws.com",
                        inline_policy=_allow(["sns:Publish"], topic_arn))
    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw2-sns")
    rid = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="publish")["id"]
    ag.put_method(restApiId=api_id, resourceId=rid, httpMethod="POST", authorizationType="NONE",
                  requestParameters={"method.request.header.x-color": True})
    ag.put_integration(
        restApiId=api_id, resourceId=rid, httpMethod="POST", type="AWS",
        integrationHttpMethod="POST", uri=f"arn:aws:apigateway:{ctx.region}:sns:path//",
        credentials=role["arn"], passthroughBehavior="NEVER",
        requestParameters={
            "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"},
        requestTemplates={"application/json": _REQUEST_TEMPLATE.replace("__TOPIC__", topic_arn)},
    )
    ag.put_method_response(restApiId=api_id, resourceId=rid, httpMethod="POST", statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=rid, httpMethod="POST",
                                statusCode="200",
                                responseTemplates={"application/json": _RESPONSE_TEMPLATE})
    _deploy_stage(ctx, api_id, "live")
    url = _rest_invoke_url(ctx, api_id, "live", "/publish")

    raw1 = json.dumps({"order": ctx.unique_name("o-"), "qty": 7, "note": "a&b=c+d"}).encode()
    _, _, t = _poll_http(url, accept=lambda s, t: s == 200 and '"published": true' in t,
                         body=raw1, headers={"Content-Type": "application/json", "x-color": color},
                         description="SNS Publish through the AWS non-proxy integration")
    mid1 = json.loads(t)["messageId"]
    assert mid1 and "$" not in mid1, f"response template did not extract a MessageId: {t!r}"

    env = _drain_until(ctx, env_q, lambda ms: any(_env(m)["MessageId"] == mid1 for m in ms))
    envelope = next(_env(m) for m in env if _env(m)["MessageId"] == mid1)
    assert envelope["TopicArn"] == topic_arn, f"envelope TopicArn {envelope['TopicArn']!r}"
    assert envelope["Message"] == raw1.decode(), (
        f"SNS Message at the subscriber {envelope['Message']!r} != client body {raw1.decode()!r}")
    assert envelope.get("MessageAttributes") == {
        "color": {"Type": "String", "Value": color},
        "qty": {"Type": "Number", "Value": "7"},
    }, f"envelope MessageAttributes were {envelope.get('MessageAttributes')!r}"

    rawm = _drain_until(ctx, raw_q, lambda ms: len(ms) >= 1)
    assert len(rawm) == 1 and rawm[0]["Body"] == raw1.decode(), (
        f"raw subscriber got {[m['Body'] for m in rawm]!r}, expected exactly the client body")
    attrs = rawm[0].get("MessageAttributes", {})
    assert attrs == {
        "color": {"StringValue": color, "DataType": "String"},
        "qty": {"StringValue": "7", "DataType": "Number"},
    }, f"raw-delivery SQS MessageAttributes were {attrs!r}"

    # Differential barrier: one publish whose header does NOT match the filter. Its arrival
    # at the unfiltered queue bounds its absence at the filtered one.
    raw2 = json.dumps({"order": "decoy", "qty": 1}).encode()
    st, _, t = _http("POST", url, body=raw2,
                     headers={"Content-Type": "application/json", "x-color": color + "-other"})
    assert st == 200, f"decoy publish failed: {st} {t[:300]!r}"
    mid2 = json.loads(t)["messageId"]
    env = _drain_until(ctx, env_q, lambda ms: any(_env(m)["MessageId"] == mid2 for m in ms))
    decoy = next(_env(m) for m in env if _env(m)["MessageId"] == mid2)
    assert decoy["MessageAttributes"]["color"]["Value"] == color + "-other", (
        f"decoy color attribute arrived as {decoy['MessageAttributes']!r}")

    # Reachability leg: a matching publish after the decoy reaches the filtered queue, and it
    # is the ONLY thing that does.
    raw3 = json.dumps({"order": "after", "qty": 3}).encode()
    st, _, t = _http("POST", url, body=raw3,
                     headers={"Content-Type": "application/json", "x-color": color})
    assert st == 200, f"third publish failed: {st} {t[:300]!r}"
    rawm = _drain_until(ctx, raw_q, lambda ms: any(m["Body"] == raw3.decode() for m in ms))
    assert [m["Body"] for m in rawm] == [raw3.decode()], (
        f"filtered raw subscriber received {[m['Body'] for m in rawm]!r}; the decoy whose "
        f"color attribute did not match must be absent")


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-"), "sim2real": CHECK}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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
