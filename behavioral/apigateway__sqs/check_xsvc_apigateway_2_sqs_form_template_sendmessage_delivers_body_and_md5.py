"""xsvc-apigateway-2-sqs-form-template-sendmessage-delivers-body-and-md5."""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-2-sqs-form-template-sendmessage-delivers-body-and-md5"
GROUP = "data-format"
SERVICES = ["apigateway", "sqs"]

# The client's raw JSON body is form-encoded into an SQS Query SendMessage by VTL. It carries
# every character the encoding has to get right: '&' and '=' (form delimiters), '+' (decodes
# to a space if left raw), '%' (double-decoding bait) and a multi-byte UTF-8 character.
_REQUEST_TEMPLATE = "Action=SendMessage&MessageBody=$util.urlEncode($input.body)"

# The SQS SendMessage reply is mapped into a client-shaped document; nothing of the raw
# SendMessageResponse envelope may survive the mapping.
_RESPONSE_TEMPLATE = (
    '{"queued": true, '
    '"messageId": "$input.path(\'$.SendMessageResponse.SendMessageResult.MessageId\')", '
    '"md5": "$input.path(\'$.SendMessageResponse.SendMessageResult.MD5OfMessageBody\')", '
    '"gatewayRequestId": "$context.requestId"}'
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A non-proxy SQS integration turns a POST into SendMessage: the consumer receives the exact body,
    the reported MD5 matches the sent bytes, and the mapped MessageId is the queued message's id."""
    acct = _account_id(ctx)
    sqs = ctx.client("sqs")
    queue_name = _xname(ctx, "apigw2-q")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role = _create_role(ctx, "apigateway.amazonaws.com",
                        inline_policy=_allow(["sqs:SendMessage"], queue_arn))

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw2-sqs")
    res_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="enqueue")["id"]
    ag.put_method(restApiId=api_id, resourceId=res_id, httpMethod="POST", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=res_id, httpMethod="POST", type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{ctx.region}:sqs:path/{acct}/{queue_name}",
        credentials=role["arn"], passthroughBehavior="NEVER",
        requestParameters={
            "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"},
        requestTemplates={"application/json": _REQUEST_TEMPLATE},
    )
    ag.put_method_response(restApiId=api_id, resourceId=res_id, httpMethod="POST",
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=res_id, httpMethod="POST",
                                statusCode="200",
                                responseTemplates={"application/json": _RESPONSE_TEMPLATE})
    _deploy_stage(ctx, api_id, "live")
    url = _rest_invoke_url(ctx, api_id, "live", "/enqueue")

    marker = ctx.unique_name("ord-")
    raw = json.dumps({"order": marker, "note": "a&b=c+d 100% café"},
                     ensure_ascii=False).encode("utf-8")
    expected_md5 = hashlib.md5(raw).hexdigest()

    status, headers, text = _poll_http(
        url, accept=lambda s, t: s == 200 and '"queued"' in t, body=raw,
        headers={"Content-Type": "application/json"},
        description="SQS SendMessage through the AWS non-proxy integration")
    mapped = json.loads(text)
    assert set(mapped) == {"queued", "messageId", "md5", "gatewayRequestId"}, (
        f"integration response template did not shape the reply; got keys {sorted(mapped)!r}: "
        f"{text[:300]!r}")
    assert mapped["md5"] == expected_md5, (
        f"MD5OfMessageBody mapped from SQS is {mapped['md5']!r}, but md5 of the bytes sent is "
        f"{expected_md5!r} - the body was altered between the client and SQS")
    assert mapped["messageId"] and "$" not in mapped["messageId"], (
        f"MessageId was not extracted by the response template: {mapped['messageId']!r}")
    assert mapped["gatewayRequestId"] == headers.get("x-amzn-requestid"), (
        f"$context.requestId in the response template ({mapped['gatewayRequestId']!r}) differs "
        f"from the x-amzn-RequestId header ({headers.get('x-amzn-requestid')!r})")

    msg = _receive_one(ctx, queue_url, description=f"message {mapped['messageId']!r} on the queue")
    assert msg["MessageId"] == mapped["messageId"], (
        f"queue holds message {msg['MessageId']!r}, but the gateway reported "
        f"{mapped['messageId']!r}")
    assert msg["Body"].encode("utf-8") == raw, (
        f"body at the consumer {msg['Body']!r} is not byte-identical to the client body "
        f"{raw.decode('utf-8')!r} - url-encode/form-decode is not a faithful round trip")
    assert msg["MD5OfBody"] == expected_md5, (
        f"ReceiveMessage MD5OfBody {msg['MD5OfBody']!r} != recomputed {expected_md5!r}")
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    # The same front door is a pipe, not a cache: a second, different body yields a second,
    # distinct message whose MD5 again matches its own bytes.
    raw2 = json.dumps({"order": marker, "seq": 2}).encode("utf-8")
    status2, _, text2 = _http("POST", url, body=raw2, headers={"Content-Type": "application/json"})
    assert status2 == 200, f"second send through the warm stage returned {status2}: {text2[:300]!r}"
    mapped2 = json.loads(text2)
    assert mapped2["messageId"] != mapped["messageId"], (
        f"two sends were reported with one MessageId {mapped2['messageId']!r}")
    assert mapped2["md5"] == hashlib.md5(raw2).hexdigest(), (
        f"second MD5 {mapped2['md5']!r} != md5 of its own body")
    msg2 = _receive_one(ctx, queue_url, description="second message on the queue")
    assert (msg2["MessageId"], msg2["Body"]) == (mapped2["messageId"], raw2.decode()), (
        f"second consumer read was {(msg2['MessageId'], msg2['Body'])!r}, expected "
        f"{(mapped2['messageId'], raw2.decode())!r}")
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg2["ReceiptHandle"])



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
    """The AWS error code fn() raised; raises if fn() succeeds, so an accepted call is never
    reported as a code mismatch."""
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


def _receive_one(ctx, queue_url, *, timeout_s=60.0, description="message"):
    """Long-poll the queue until exactly one message is returned; return it."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5, MessageAttributeNames=["All"],
                                   VisibilityTimeout=60).get("Messages", [])
        if msgs:
            assert len(msgs) == 1, f"expected one message, the queue returned {len(msgs)}: {msgs!r}"
            return msgs[0]
    raise AssertionError(f"{description} never arrived within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
