"""xsvc-apigateway-2-sqs-role-missing-sendmessage-denied-surfaces-access-denied."""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-apigateway-2-sqs-role-missing-sendmessage-denied-surfaces-access-denied"
GROUP = "permission-chain"
SERVICES = ["apigateway", "sqs"]

_REQUEST_TEMPLATE = "Action=SendMessage&MessageBody=$util.urlEncode($input.body)"
_OK_TEMPLATE = (
    '{"queued": true, '
    '"messageId": "$input.path(\'$.SendMessageResponse.SendMessageResult.MessageId\')"}'
)
# Selected only when the BACKEND (SQS) answered 4xx: the SQS error document is surfaced to the
# client as a 403 carrying SQS's own code and type.
_ERR_TEMPLATE = (
    '{"queued": false, "surfacedCode": "$input.path(\'$.Error.Code\')", '
    '"surfacedType": "$input.path(\'$.Error.Type\')"}'
)


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An integration role without sqs:SendMessage is refused by SQS, surfaced as 403 AccessDenied with
    nothing queued, while a granted twin route delivers; granting the action makes the route deliver."""
    acct = _account_id(ctx)
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    queue_name = _xname(ctx, "apigw2-q")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    granted = _create_role(ctx, "apigateway.amazonaws.com",
                           inline_policy=_allow(["sqs:SendMessage"], queue_arn))
    denied = _create_role(ctx, "apigateway.amazonaws.com",
                          inline_policy=_allow(["sqs:GetQueueAttributes"], queue_arn))

    ag = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx, kind="apigw2-sqsdeny")
    for path, role in (("granted", granted), ("denied", denied)):
        rid = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart=path)["id"]
        ag.put_method(restApiId=api_id, resourceId=rid, httpMethod="POST",
                      authorizationType="NONE")
        ag.put_integration(
            restApiId=api_id, resourceId=rid, httpMethod="POST", type="AWS",
            integrationHttpMethod="POST",
            uri=f"arn:aws:apigateway:{ctx.region}:sqs:path/{acct}/{queue_name}",
            credentials=role["arn"], passthroughBehavior="NEVER",
            requestParameters={
                "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"},
            requestTemplates={"application/json": _REQUEST_TEMPLATE},
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

    # Beat 1 - positive control: the granted twin delivers.
    _, _, t = _poll_http(url_ok, accept=lambda s, t: s == 200 and '"queued": true' in t,
                         body=body("control"), headers=hdrs, description="granted twin route")
    control_id = json.loads(t)["messageId"]

    # Beats 2+3 - the denied route: polled only past the role's assume-propagation window
    # (500), never past the refusal itself.
    st, _, t = _poll_http(url_no, accept=lambda s, t: s in (200, 403), body=body("denied"),
                          headers=hdrs, description="denied route")
    assert st == 403, f"role without sqs:SendMessage was NOT refused: {st} {t[:300]!r}"
    err = json.loads(t)
    assert err == {"queued": False, "surfacedCode": "AccessDenied", "surfacedType": "Sender"}, (
        f"SQS's refusal was not surfaced by the 4xx integration response as "
        f"AccessDenied/Sender; got {err!r}")

    # Beat 4 - effect absent, bounded by a differential barrier: a granted send issued after
    # the refusal must arrive, and only granted markers may ever appear.
    st, _, t = _http("POST", url_ok, body=body("barrier"), headers=hdrs)
    assert st == 200, f"granted twin stopped delivering: {st} {t[:300]!r}"
    barrier_id = json.loads(t)["messageId"]
    seen = _drain_until(ctx, queue_url, {control_id, barrier_id})
    bodies = sorted(json.loads(m["Body"])["marker"] for m in seen.values())
    assert bodies == sorted([f"{tag}-control", f"{tag}-barrier"]), (
        f"queue held {bodies!r}; the denied route's message must be absent")

    # Beats 5+6 - repair the one missing action and the identical route delivers.
    iam.put_role_policy(RoleName=denied["name"], PolicyName="inline",
                        PolicyDocument=json.dumps(
                            _allow(["sqs:GetQueueAttributes", "sqs:SendMessage"], queue_arn)))
    _, _, t = _poll_http(url_no, accept=lambda s, t: s == 200 and '"queued": true' in t,
                         body=body("repaired"), headers=hdrs, timeout_s=120.0,
                         description="denied route after granting sqs:SendMessage")
    repaired_id = json.loads(t)["messageId"]
    seen = _drain_until(ctx, queue_url, {repaired_id})
    assert json.loads(seen[repaired_id]["Body"])["marker"] == f"{tag}-repaired", (
        f"repaired route delivered {seen[repaired_id]['Body']!r}")
    leaked = [m["Body"] for m in seen.values() if f"{tag}-denied" in m["Body"]]
    assert not leaked, f"a message refused with AccessDenied reached the queue: {leaked!r}"



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


def _drain_until(ctx, queue_url, want_ids, *, timeout_s=60.0):
    """Receive+delete until every id in want_ids was seen; return {MessageId: message} of
    EVERYTHING received meanwhile, so the caller can assert nothing else arrived."""
    sqs = ctx.client("sqs")
    seen = {}
    deadline = time.monotonic() + timeout_s
    while not set(want_ids) <= set(seen):
        if time.monotonic() > deadline:
            raise AssertionError(f"messages {sorted(set(want_ids) - set(seen))!r} never arrived "
                                 f"within {timeout_s}s; saw {sorted(seen)!r}")
        for m in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5, MessageAttributeNames=["All"],
                                     AttributeNames=["All"]).get("Messages", []):
            seen[m["MessageId"]] = m
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
