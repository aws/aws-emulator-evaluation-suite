"""apigw-response-compression-gzips-above-the-minimum-and-not-below."""
from __future__ import annotations

import gzip
import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-response-compression-gzips-above-the-minimum-and-not-below"
GROUP = 'methods-integrations'
SERVICES = ['apigateway']

_THRESHOLD = 1024


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so a throttle can
    be unrelated to the claim."""
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
    so the name, the description AND the tag all carry the sim2real marker."""
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


def _raw_http(url, headers):
    """GET returning (status, lowercased headers, RAW UNDECODED body bytes).

    urllib is used deliberately and the bytes are never handed to a decoder: it neither
    sends Accept-Encoding: gzip by default nor transparently inflates a gzip response, so
    the compression is observable at all. A client library that auto-decodes would make
    every assertion below vacuously true."""
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read())


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage: the real-AWS execute-api vhost, or the emulator's
    /_aws/execute-api/<id>/<stage>/ route."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_raw(url, headers, predicate, *, timeout_s=150.0, interval_s=3.0,
              description="stage response"):
    """Re-issue a raw GET until predicate(status, headers, raw) holds, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, raw = _raw_http(url, headers)
        if predicate(status, resp_headers, raw):
            return status, resp_headers, raw
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=({status}, {raw[:120]!r})"
            )
        time.sleep(interval_s)


def _mock_literal_route(ctx, ag, api_id, path_part, literal):
    """GET /<path_part> on a MOCK integration returning *literal* verbatim."""
    resource_id = _child(ctx, ag, api_id, path_part)
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="NONE",
    ))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode":200}'},
    ))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
    ))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": literal},
    ))
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """With minimumCompressionSize set, a response above the threshold comes back
    Content-Encoding: gzip and inflates to the byte-exact original, a response below the
    threshold comes back uncompressed, and a client that does not offer gzip gets plain bytes."""
    ag = ctx.client("apigateway")

    marker = f"sim2real-{_unique_token()}"
    big_literal = json.dumps({"marker": marker, "pad": "z" * 3900}, separators=(",", ":"))
    small_literal = json.dumps({"marker": marker}, separators=(",", ":"))
    big_expected = big_literal.encode()
    small_expected = small_literal.encode()
    assert len(big_expected) > _THRESHOLD > len(small_expected), (
        f"precondition on the fixture itself: {len(big_expected)} must be above and "
        f"{len(small_expected)} below the {_THRESHOLD}-byte threshold"
    )

    api_id = _create_api(ctx, ag, "response-compression")
    _retry_throttled(lambda: ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/minimumCompressionSize",
                          "value": str(_THRESHOLD)}],
    ))
    configured = ag.get_rest_api(restApiId=api_id).get("minimumCompressionSize")
    assert configured == _THRESHOLD, (
        f"precondition: UpdateRestApi must have stored minimumCompressionSize "
        f"{_THRESHOLD!r}, got {configured!r}"
    )

    _mock_literal_route(ctx, ag, api_id, "big", big_literal)
    _mock_literal_route(ctx, ag, api_id, "small", small_literal)

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="test", deploymentId=deployment_id,
        tags={"sim2real": "response-compression"},
    ))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="test")))

    big_url = _apigw_url(ctx, api_id, "test", "/big")
    small_url = _apigw_url(ctx, api_id, "test", "/small")
    gzip_hdr = {"Accept-Encoding": "gzip"}

    _bs, big_headers, big_raw = _poll_raw(
        big_url, gzip_hdr, lambda s, h, r: s == 200,
        description=f"GET {big_url} to be served by the deployed stage",
    )
    assert big_headers.get("content-encoding") == "gzip", (
        f"expected Content-Encoding: gzip for a {len(big_expected)}-byte body over a "
        f"{_THRESHOLD}-byte threshold, got {big_headers.get('content-encoding')!r} "
        f"(all headers {big_headers!r})"
    )
    inflated = gzip.decompress(big_raw)
    assert inflated == big_expected, (
        f"the gzip round trip lost bytes: inflated {len(inflated)} bytes, expected "
        f"{len(big_expected)}; first difference near {inflated[:60]!r} vs "
        f"{big_expected[:60]!r}"
    )
    assert len(big_raw) < len(big_expected), (
        f"Content-Encoding said gzip but the transfer was not smaller: {len(big_raw)} "
        f"raw bytes >= {len(big_expected)} uncompressed"
    )

    _ss, small_headers, small_raw = _raw_http(small_url, gzip_hdr)
    assert "content-encoding" not in small_headers, (
        f"a {len(small_expected)}-byte body was compressed under a {_THRESHOLD}-byte "
        f"threshold: {small_headers!r}"
    )
    assert small_raw == small_expected, (
        f"the below-threshold body must arrive verbatim, got {small_raw!r}"
    )

    # urllib sends Accept-Encoding: identity when we do not override it.
    _ps, plain_headers, plain_raw = _raw_http(big_url, {})
    assert plain_raw == big_expected, (
        f"a client that does not offer gzip must get the plain {len(big_expected)} bytes, "
        f"got {len(plain_raw)} bytes starting {plain_raw[:40]!r} "
        f"(content-encoding {plain_headers.get('content-encoding')!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
