"""apigw-vtl-request-and-response-templates-transform-a-real-body."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-vtl-request-and-response-templates-transform-a-real-body"
GROUP = 'methods-integrations'
SERVICES = ['apigateway']


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so a burst of
    PutIntegration/CreateDeployment calls can surface as a throttle that has nothing to do
    with what is being graded."""
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


def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _create_api(ctx, ag, scenario):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    A REST API's only handle is a server-minted id,
    so the name, description AND tag all carry the sim2real marker."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": scenario},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id


def _http(method, url, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=150.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A deployment becomes servable on its stage asynchronously, so the first touch of a
    freshly deployed stage polls to a condition with a bounded deadline rather than
    sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _mock_branch(ctx, ag, api_id, resource_id, method, request_template, bodies):
    """A MOCK integration whose request template picks the status, plus one integration
    response per (status, literal body) pair in *bodies*."""
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=method,
        authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=method, type="MOCK",
        requestTemplates={"application/json": request_template},
    ))
    for status_code, literal in bodies.items():
        _retry_throttled(lambda sc=status_code: ag.put_method_response(
            restApiId=api_id, resourceId=resource_id, httpMethod=method, statusCode=sc,
        ))
        _retry_throttled(lambda sc=status_code, lit=literal: ag.put_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod=method, statusCode=sc,
            selectionPattern="" if sc == "200" else sc[0] + r"\d{2}",
            responseTemplates={"application/json": lit},
        ))


def _deploy(ctx, ag, api_id):
    """CreateDeployment + a uniquely named stage (registered for teardown)."""
    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    stage = "test"
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=deployment_id,
        tags={"sim2real": "vtl-templates"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))
    return stage
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A request mapping template rewrites the client body before the integration sees it (a
    backend API answers 200 only for the exact rewritten body), and a response mapping template
    rewrites the integration's body before the client sees it, in one real HTTP round trip."""
    ag = ctx.client("apigateway")

    name = f"sim2real-{_unique_token()}"
    match_marker = "len-and-name-match"
    quote_marker = "escaped-quote-survived"
    quoted_value = 'A"B'

    # ---- backend API: it verifies, server-side, exactly what body it was handed ----
    backend_id = _create_api(ctx, ag, "vtl-templates-backend")
    backend_named = _child(ctx, ag, backend_id, "a")
    _mock_branch(
        ctx, ag, backend_id, backend_named, "POST",
        "#set($seen = $input.path('$.seen'))\n"
        "#set($len = $input.path('$.len'))\n"
        f'#if($seen == "{name}" && $len == {len(name)})\n'
        '{"statusCode":200}\n'
        "#else\n"
        '{"statusCode":404}\n'
        "#end",
        {"200": '{"backend_saw":"%s"}' % match_marker,
         "404": '{"backend_saw":"mismatch"}'},
    )
    backend_quoted = _child(ctx, ag, backend_id, "q")
    _mock_branch(
        ctx, ag, backend_id, backend_quoted, "POST",
        "#set($seen = $input.path('$.seen'))\n"
        f"#if($seen.length() == {len(quoted_value)} "
        f"&& $input.path('$.len') == {len(quoted_value)})\n"
        '{"statusCode":200}\n'
        "#else\n"
        '{"statusCode":404}\n'
        "#end",
        {"200": '{"backend_saw":"%s"}' % quote_marker,
         "404": '{"backend_saw":"mismatch"}'},
    )
    backend_stage = _deploy(ctx, ag, backend_id)
    # rstrip: _apigw_url with an empty path leaves a trailing slash, and PutIntegration
    # rejects the resulting double slash with "Invalid HTTP endpoint specified for URI".
    backend_base = _apigw_url(ctx, backend_id, backend_stage).rstrip("/")

    # Precondition, not the claim: the backend serves and really does discriminate. Sent
    # directly (no front API in the path) it must 404 on the CLIENT-shaped body, which is
    # what makes the front API's later 200 evidence of a rewrite.
    _poll_http(
        backend_base + "/a", lambda s, h, t: s == 404, method="POST",
        body=json.dumps({"name": name}).encode(),
        headers={"Content-Type": "application/json"},
        description=f"POST {backend_base}/a to be served and reject an un-rewritten body",
    )

    # ---- front API: its request template does the rewrite, its response template the ----
    # ---- second transformation                                                       ----
    front_id = _create_api(ctx, ag, "vtl-templates-front")
    front_response_200 = (
        "#set($v=$input.path('$.backend_saw'))"
        '{"upper":"$v.toUpperCase()","len":$v.length(),"stage":"$context.stage"}'
    )
    for path_part, backend_path in (("t", "a"), ("q", "q")):
        resource_id = _child(ctx, ag, front_id, path_part)
        _retry_throttled(lambda rid=resource_id: ag.put_method(
            restApiId=front_id, resourceId=rid, httpMethod="POST",
            authorizationType="NONE",
        ))
        _retry_throttled(lambda rid=resource_id, bp=backend_path: ag.put_integration(
            restApiId=front_id, resourceId=rid, httpMethod="POST", type="HTTP",
            integrationHttpMethod="POST", uri=f"{backend_base}/{bp}",
            requestTemplates={"application/json": (
                '{"seen":"$util.escapeJavaScript($input.path(\'$.name\'))",'
                "\"len\":$input.path('$.name').length()}"
            )},
        ))
        for status_code, literal in (("200", front_response_200),
                                    ("404", '{"rejected_by_backend":true}')):
            _retry_throttled(lambda rid=resource_id, sc=status_code: ag.put_method_response(
                restApiId=front_id, resourceId=rid, httpMethod="POST", statusCode=sc,
            ))
            _retry_throttled(
                lambda rid=resource_id, sc=status_code, lit=literal:
                ag.put_integration_response(
                    restApiId=front_id, resourceId=rid, httpMethod="POST", statusCode=sc,
                    selectionPattern="" if sc == "200" else r"4\d{2}",
                    responseTemplates={"application/json": lit},
                )
            )
    front_stage = _deploy(ctx, ag, front_id)
    front_base = _apigw_url(ctx, front_id, front_stage).rstrip("/")

    hdrs = {"Content-Type": "application/json"}
    status, _h, text = _poll_http(
        front_base + "/t", lambda s, h, t: s in (200, 404), method="POST",
        body=json.dumps({"name": name}).encode(), headers=hdrs,
        description=f"POST {front_base}/t to be served by the deployed stage",
    )
    assert status == 200, (
        f"expected 200 — the backend answers 200 only when the request mapping template "
        f"rewrote {{'name': ...}} into {{'seen': {name!r}, 'len': {len(name)}}} — got "
        f"{status!r}: {text!r}"
    )
    payload = json.loads(text)
    assert set(payload) == {"upper", "len", "stage"}, (
        f"the response template did not shape the body; the integration returned "
        f"backend_saw and the client should see upper/len/stage, got {payload!r}"
    )
    assert payload["upper"] == match_marker.upper(), (
        f"expected the response template to upper-case the integration's "
        f"{match_marker!r} to {match_marker.upper()!r}, got {payload['upper']!r}"
    )
    assert payload["len"] == len(match_marker), (
        f"expected the response template's own $v.length() to compute "
        f"{len(match_marker)!r} over {match_marker!r}, got {payload['len']!r}"
    )
    assert payload["stage"] == front_stage, (
        f"expected $context.stage to resolve to {front_stage!r} at request time, got "
        f"{payload['stage']!r}"
    )

    # $util.escapeJavaScript is load-bearing: without it the request template emits
    # {"seen":"A"B",...}, which is not JSON, and the backend cannot read $.len at all.
    q_status, _qh, q_text = _http(
        "POST", front_base + "/q",
        body=json.dumps({"name": quoted_value}).encode(), headers=hdrs,
    )
    assert q_status == 200, (
        f"expected 200 — the backend sees a well-formed body of length "
        f"{len(quoted_value)} only if escapeJavaScript escaped the quote in "
        f"{quoted_value!r} — got {q_status!r}: {q_text!r}"
    )
    assert json.loads(q_text)["upper"] == quote_marker.upper(), (
        f"expected {quote_marker.upper()!r} through the response template, got "
        f"{json.loads(q_text)!r}"
    )

    # Control: the 200s above are not vacuous — the backend really compares, so a body
    # the request template maps to a DIFFERENT value comes back 404 through the same
    # deployed front stage.
    wrong_status, _wh, wrong_text = _http(
        "POST", front_base + "/t",
        body=json.dumps({"name": f"sim2real-{_unique_token()}"}).encode(), headers=hdrs,
    )
    assert wrong_status == 404, (
        f"control: a name the backend template does not hard-code must come back 404, so "
        f"the 200 above is evidence of the rewrite; got {wrong_status!r}: {wrong_text!r}"
    )
    assert json.loads(wrong_text) == {"rejected_by_backend": True}, (
        f"control: expected the front API's 404 response template, got {wrong_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
