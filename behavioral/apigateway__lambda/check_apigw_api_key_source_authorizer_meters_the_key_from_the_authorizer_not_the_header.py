"""apigw-api-key-source-authorizer-meters-the-key-from-the-authorizer-not-the-header."""
from __future__ import annotations

import io
import json
import random
import string
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags

CHECK = "apigw-api-key-source-authorizer-meters-the-key-from-the-authorizer-not-the-header"
GROUP = "usage-plans-keys"
SERVICES = ["apigateway", "lambda"]

# Bounds usage-plan key association reaching the edge and the header being dropped from
# consideration, which can lag the first admission.
_PROPAGATION_S = 240.0


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff."""
    from botocore.exceptions import ClientError
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _ignore_not_found(fn):
    """Teardown helper: already-gone is not a cleanup failure; anything else still raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException",
                                                "ResourceNotFoundException", "NoSuchEntity"):
            raise


def _delete_usage_plan(ag, plan_id, api_id, stage):
    """DeleteUsagePlan refuses while an API stage is associated, so detach the stage first."""
    _ignore_not_found(lambda: _retry_throttled(lambda: ag.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[{"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage}"}])))
    _ignore_not_found(lambda: _retry_throttled(lambda: ag.delete_usage_plan(usagePlanId=plan_id)))


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry; RAISES on the deadline rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s, last={last!r}")


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _http(method, url, headers=None, timeout=30.0):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode(errors="replace"))


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _authorizer_zip(good_key, bogus_key):
    """A REQUEST authorizer that always ALLOWS, and chooses which usageIdentifierKey to
    return from the caller's `x-key-mode` header — so the metering key, and only the metering
    key, is what varies between the legs below."""
    code = f"""
_GOOD = {good_key!r}
_BOGUS = {bogus_key!r}


def handler(event, context):
    headers = event.get("headers") or {{}}
    mode = "good"
    for name, value in headers.items():
        if name.lower() == "x-key-mode":
            mode = value
    return {{
        "principalId": "sim2real-user",
        "usageIdentifierKey": _GOOD if mode == "good" else _BOGUS,
        "policyDocument": {{
            "Version": "2012-10-17",
            "Statement": [{{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": event["methodArn"],
            }}],
        }},
    }}
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With apiKeySource=AUTHORIZER the authorizer's usageIdentifierKey meters the request and
    x-api-key is ignored; flipping to HEADER and redeploying inverts every outcome.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-key-source.html
    """
    ag = ctx.client("apigateway")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    marker = f"sim2real-{_unique_token()}"
    # Distinct from `marker`: the customised INVALID_API_KEY gateway response embeds this one,
    # and `marker` must never appear inside it, or "the refused response must not carry the
    # integration marker" is vacuously true/false regardless of what AWS actually did.
    gw_marker = f"sim2realgw-{_unique_token()}"
    good_key_value = f"sim2realgood{_unique_token(20)}"    # >= 20 chars, as API keys require
    bogus_key_value = f"sim2realbogus{_unique_token(20)}"  # syntactically valid, never created

    # ---- authorizer function -----------------------------------------------------------
    role_name = ctx.unique_name("sim2real-behav-apikeysrc-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    basic = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic)))

    function_name = ctx.unique_name("sim2real-behav-apikeysrc-fn-")

    def _try_create():
        from botocore.exceptions import ClientError
        try:
            return lam.create_function(
                FunctionName=function_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _authorizer_zip(good_key_value, bogus_key_value)},
                Timeout=15, Tags={"sim2real": CHECK})
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None      # the role is not assumable by Lambda yet; retry
            raise

    function_arn = _poll_until(
        _try_create, lambda result: result is not None, timeout_s=90.0, interval_s=3.0,
        description="the new IAM role becoming assumable so CreateFunction succeeds",
    )["FunctionArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: lam.delete_function(FunctionName=function_name)))

    # ---- the API: key sourced from the AUTHORIZER ---------------------------------------
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]}, apiKeySource="AUTHORIZER",
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    created = ag.get_rest_api(restApiId=api_id)
    assert created.get("apiKeySource") == "AUTHORIZER", (
        f"expected GetRestApi to report apiKeySource='AUTHORIZER' as created, got "
        f"{created.get('apiKeySource')!r}"
    )

    authorizer_id = _retry_throttled(lambda: ag.create_authorizer(
        restApiId=api_id, name=ctx.unique_name("sim2real-behav-authorizer-"),
        type="REQUEST",
        authorizerUri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                       f"{function_arn}/invocations"),
        identitySource="method.request.header.x-key-mode",
        authorizerResultTtlInSeconds=0))["id"]
    lam.add_permission(
        FunctionName=function_name, StatementId="apigw-invoke-authorizer",
        Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
        SourceArn=(f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/"
                   f"{authorizer_id}"))

    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart="metered"))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="CUSTOM", authorizerId=authorizer_id, apiKeyRequired=True))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"marker":"%s"}' % marker}))
    _retry_throttled(lambda: ag.put_gateway_response(
        restApiId=api_id, responseType="INVALID_API_KEY",
        responseTemplates={"application/json":
                           '{"gw":"invalidkey-%s","type":"$context.error.responseType"}'
                           % gw_marker}))

    stage = f"s{_unique_token()}"
    deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    # ---- the key and the usage plan that makes it meaningful ----------------------------
    key_id = _retry_throttled(lambda: ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"), value=good_key_value, enabled=True,
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ag.delete_api_key(apiKey=key_id)))
    plan_id = _retry_throttled(lambda: ag.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage}],
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(ag, plan_id, api_id, stage))
    plan_key_id = _retry_throttled(lambda: ag.create_usage_plan_key(
        usagePlanId=plan_id, keyId=key_id, keyType="API_KEY"))["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ag.delete_usage_plan_key(
        usagePlanId=plan_id, keyId=plan_key_id)))

    # A second, stronger key: real, enabled, but never added to ANY usage plan — a header
    # carrying this proves the header is not merely "not found", it is not consulted at all.
    orphan_key_value = f"sim2realorphan{_unique_token(20)}"
    orphan_key_id = _retry_throttled(lambda: ag.create_api_key(
        name=ctx.unique_name("sim2real-behav-orphankey-"), value=orphan_key_value, enabled=True,
        tags={"sim2real": CHECK}))["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ag.delete_api_key(apiKey=orphan_key_id)))

    url = _apigw_url(ctx, api_id, stage, "/metered")
    good_mode = {"x-key-mode": "good"}
    bogus_mode = {"x-key-mode": "bogus"}

    def _get(headers):
        return _http("GET", url, headers=headers)

    # ---- AUTHORIZER: the positive control, with NO x-api-key header at all --------------
    status, _h, text = _poll_until(
        lambda: _get(good_mode), lambda r: r[0] == 200, timeout_s=_PROPAGATION_S,
        interval_s=8.0,
        description=(
            f"GET {url} with NO x-api-key header to be ADMITTED because the authorizer "
            f"returned a usageIdentifierKey associated with the usage plan"
        ),
    )
    assert marker in text, (
        f"positive control: the admitted request must reach the integration and return marker "
        f"{marker!r}, got {status} body {text[:200]!r}"
    )

    # ---- AUTHORIZER: an unassociated usageIdentifierKey is refused ----------------------
    b_status, _bh, b_text = _get(bogus_mode)
    assert b_status == 403, (
        f"expected 403 when the authorizer returns a usageIdentifierKey matching no API key "
        f"(and apiKeyRequired is set), got {b_status} body {b_text[:200]!r}"
    )
    assert marker not in b_text, (
        f"effect-absent: the refused request must not reach the integration, so the response "
        f"must not carry {marker!r}; got {b_text[:200]!r}"
    )
    refused = json.loads(b_text)
    assert refused.get("gw") == f"invalidkey-{gw_marker}", (
        f"expected the customised INVALID_API_KEY gateway response (marker "
        f"'invalidkey-{gw_marker}') to be served, got {refused!r} — ACCESS_DENIED, UNAUTHORIZED "
        f"and DEFAULT_4XX are also 403 and would be the wrong classification"
    )
    assert refused.get("type") == "INVALID_API_KEY", (
        f"expected $context.error.responseType to substitute to 'INVALID_API_KEY', got "
        f"{refused.get('type')!r} (full body {refused!r})"
    )

    # ---- AUTHORIZER: the x-api-key header is IGNORED, in both directions ----------------
    # The refusal-side leg is single-shot by design: a polling window could mask a transient
    # fail-OPEN moment as a false pass.
    ignored_status, _ih, ignored_text = _get({**bogus_mode, "x-api-key": good_key_value})
    assert ignored_status == 403, (
        f"expected 403 even though a VALID x-api-key header was attached: with "
        f"apiKeySource=AUTHORIZER the header must be ignored and the authorizer's bogus "
        f"usageIdentifierKey must decide. Got {ignored_status} body {ignored_text[:200]!r} — a "
        f"200 here is a metering and tenancy bypass, because any client could forge the header"
    )
    assert json.loads(ignored_text) == {"gw": f"invalidkey-{gw_marker}", "type": "INVALID_API_KEY"}, (
        f"expected the customised INVALID_API_KEY gateway response, got {ignored_text[:200]!r}"
    )

    # The two admit-side legs poll: real AWS can take a little longer to fully drop the header
    # from consideration than it took to admit the header-less positive control above, and that
    # lag only ever manifests as a spurious 403 (fail-closed), never a spurious 200.
    admitted_status, _ah, admitted_text = _poll_until(
        lambda: _get({**good_mode, "x-api-key": bogus_key_value}),
        lambda r: r[0] == 200, timeout_s=_PROPAGATION_S, interval_s=8.0,
        description=(
            f"GET {url} with a BOGUS (never-created) x-api-key header and the authorizer "
            f"returning a VALID usageIdentifierKey to be ADMITTED — the header must not even "
            f"be checked for existence"
        ),
    )
    assert marker in admitted_text, (
        f"expected the admitted request to reach the integration and carry marker {marker!r}, "
        f"got {admitted_status} body {admitted_text[:200]!r}"
    )

    # The strongest form of "the header is ignored": a header carrying a REAL, ENABLED key that
    # simply is not on this usage plan, so a target that merely checks "does the header value
    # exist as SOME key" (rather than truly ignoring it) still fails this leg.
    orphan_status, _oh, orphan_text = _poll_until(
        lambda: _get({**good_mode, "x-api-key": orphan_key_value}),
        lambda r: r[0] == 200, timeout_s=_PROPAGATION_S, interval_s=8.0,
        description=(
            f"GET {url} with a REAL but usage-plan-unassociated x-api-key header and the "
            f"authorizer returning a VALID usageIdentifierKey to be ADMITTED"
        ),
    )
    assert marker in orphan_text, (
        f"expected the admitted request to reach the integration and carry marker {marker!r}, "
        f"got {orphan_status} body {orphan_text[:200]!r}"
    )

    # ---- INVERSION: flip to HEADER and every verdict must swap --------------------------
    _retry_throttled(lambda: ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/apiKeySource", "value": "HEADER"}]))
    flipped = ag.get_rest_api(restApiId=api_id)
    assert flipped.get("apiKeySource") == "HEADER", (
        f"expected GetRestApi to report apiKeySource='HEADER' after the patch, got "
        f"{flipped.get('apiKeySource')!r}"
    )
    redeployed = _retry_throttled(
        lambda: ag.create_deployment(restApiId=api_id, stageName=stage))["id"]
    assert redeployed != deployment, (
        f"expected a NEW deployment id for the take-effect redeploy, got {redeployed!r}"
    )

    # Under HEADER, the authorizer's good key no longer admits anything on its own.
    h_status, _hh, h_text = _poll_until(
        lambda: _get(good_mode), lambda r: r[0] == 403, timeout_s=_PROPAGATION_S,
        interval_s=8.0,
        description=(
            f"GET {url} with the authorizer returning a VALID usageIdentifierKey but no "
            f"x-api-key header to be REFUSED once apiKeySource is HEADER"
        ),
    )
    assert marker not in h_text, (
        f"under apiKeySource=HEADER a request with no x-api-key header must not reach the "
        f"integration; got {h_status} body {h_text[:200]!r}"
    )
    assert json.loads(h_text).get("type") == "INVALID_API_KEY", (
        f"expected the HEADER-mode refusal to be classified INVALID_API_KEY too, got "
        f"{json.loads(h_text)!r}"
    )

    # ...and the header now rules, even against a bogus authorizer key. This is an admit-side
    # leg, so — matching the AUTHORIZER-side legs above — it polls rather than reading once.
    hk_status, _hkh, hk_text = _poll_until(
        lambda: _get({**bogus_mode, "x-api-key": good_key_value}),
        lambda r: r[0] == 200, timeout_s=_PROPAGATION_S, interval_s=8.0,
        description=(
            f"GET {url} with a VALID x-api-key header and the authorizer returning a BOGUS "
            f"usageIdentifierKey to be ADMITTED once apiKeySource is HEADER — the exact inverse "
            f"of the 403 asserted earlier for the identical request"
        ),
    )
    assert marker in hk_text, (
        f"expected the admitted request to reach the integration and carry marker {marker!r}, "
        f"got {hk_status} body {hk_text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
