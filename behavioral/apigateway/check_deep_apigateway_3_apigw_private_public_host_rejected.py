"""deep-apigateway-3-apigw-private-public-host-rejected."""
from __future__ import annotations

import json
import socket
import ssl
import time
import http.client
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-apigateway-3-apigw-private-public-host-rejected"
GROUP = "private-endpoint"
SERVICES = ["apigateway"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A PRIVATE REST API cannot be deployed without a resource policy, and once deployed under an
    allow-all policy the public execute-api edge refuses it with 403 ForbiddenException by Host/SNI,
    while a REGIONAL twin on the same edge address serves its nonce with 200."""
    apigw = ctx.client("apigateway")
    private_nonce = f"sim2real-private-{ctx.unique_name('')}"
    public_nonce = f"sim2real-public-{ctx.unique_name('')}"

    private_id = _mock_api(ctx, apigw, "PRIVATE", private_nonce)
    created = apigw.get_rest_api(restApiId=private_id)
    assert created["endpointConfiguration"]["types"] == ["PRIVATE"], (
        f"CreateRestApi did not persist the PRIVATE endpoint type: {created['endpointConfiguration']!r}"
    )
    assert not created.get("policy"), f"a fresh private API already has a policy: {created.get('policy')!r}"

    # ---- rejection: a private API cannot be deployed with no resource policy ----
    code, message = _error(lambda: apigw.create_deployment(restApiId=private_id, stageName="s"))
    assert code == "BadRequestException", f"deploy without a policy returned {code!r} ({message!r})"
    assert message == "Private REST API doesn't have a resource policy attached to it", (
        f"unexpected rejection message {message!r}"
    )
    deployments = apigw.get_deployments(restApiId=private_id)["items"]
    assert deployments == [], f"a rejected deployment left deployments behind: {deployments!r}"
    code, message = _error(lambda: apigw.get_stage(restApiId=private_id, stageName="s"))
    assert code == "NotFoundException", f"a rejected deployment left stage 's' behind ({code!r})"
    assert message == "Invalid stage identifier specified", f"unexpected GetStage message {message!r}"

    # ---- attach a policy that allows EVERYONE, so only the endpoint type can refuse ----
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke",
        "Resource": "execute-api:/*"}]}
    apigw.update_rest_api(restApiId=private_id, patchOperations=[
        {"op": "replace", "path": "/policy", "value": json.dumps(policy)}])
    apigw.create_deployment(restApiId=private_id, stageName="s")

    # ---- positive control: the REGIONAL twin ----
    public_id = _mock_api(ctx, apigw, "REGIONAL", public_nonce)
    apigw.create_deployment(restApiId=public_id, stageName="s")

    # Both APIs are asked at ONE address, the twin's: a runner whose own network has a private
    # execute-api path cannot change which path the private API is refused on.
    twin = urllib.parse.urlsplit(ctx.rest_api_url(public_id, "s"))
    private = urllib.parse.urlsplit(ctx.rest_api_url(private_id, "s"))
    edge_ip = _poll(lambda: _resolve(twin.hostname), lambda ip: ip is not None,
                    timeout_s=180, interval_s=5, what=f"DNS for {twin.hostname}")
    fetch_public = lambda: _get_via(edge_ip, twin)  # noqa: E731
    fetch_private = lambda: _get_via(edge_ip, private)  # noqa: E731

    status, _, body = _poll(fetch_public, lambda r: r[0] == 200, timeout_s=180, interval_s=5,
                            what="REGIONAL twin serving on the public edge")
    assert json.loads(body) == {"m": public_nonce}, f"twin served {body!r}, expected its nonce"

    status, headers, body = fetch_private()
    assert status == 403, (
        f"the public edge answered the PRIVATE API with {status!r} {body!r}; it must refuse it"
    )
    assert headers.get("x-amzn-errortype", "").split(":")[0] == "ForbiddenException", (
        f"refusal carried x-amzn-ErrorType {headers.get('x-amzn-errortype')!r}"
    )
    assert json.loads(body) == {"message": "Forbidden"}, f"refusal body was {body!r}"
    assert private_nonce.encode() not in body, "the private API's content leaked to the public edge"

    # the twin still serves on the same edge right after the refusal: same moment, same address
    status, _, body = fetch_public()
    assert status == 200 and json.loads(body) == {"m": public_nonce}, (
        f"positive control regressed after the refusal: {status!r} {body!r}"
    )


def _mock_api(ctx, apigw, endpoint_type, nonce):
    api_id = apigw.create_rest_api(
        name=ctx.unique_name(f"sim2real-{endpoint_type.lower()}-"),
        endpointConfiguration={"types": [endpoint_type]}, tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore(lambda: apigw.delete_rest_api(restApiId=api_id),
                                   "NotFoundException"))
    root = next(i["id"] for i in apigw.get_resources(restApiId=api_id)["items"] if i["path"] == "/")
    apigw.put_method(restApiId=api_id, resourceId=root, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(restApiId=api_id, resourceId=root, httpMethod="GET", type="MOCK",
                          requestTemplates={"application/json": '{"statusCode": 200}'})
    apigw.put_method_response(restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": json.dumps({"m": nonce})})
    return api_id


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success is itself a failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("call succeeded where real AWS rejects it")


def _ignore(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _poll(probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last={value!r}")
        time.sleep(interval_s)


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _get_via(ip, url):
    """GET ``url`` at a fixed address, with Host (and, over TLS, SNI) naming the API to serve."""
    host, tls = url.hostname, url.scheme == "https"
    port = url.port or (443 if tls else 80)
    raw = socket.create_connection((ip, port), timeout=20)
    if tls:
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=20, context=context)
        conn.sock = context.wrap_socket(raw, server_hostname=host)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=20)
        conn.sock = raw
    try:
        conn.request("GET", f"{url.path}/", headers={"Host": url.netloc})
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
