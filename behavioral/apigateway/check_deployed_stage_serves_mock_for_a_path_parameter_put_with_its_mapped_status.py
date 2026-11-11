"""deployed-stage-serves-mock-for-a-path-parameter-put-with-its-mapped-status."""
from __future__ import annotations

import json
import random
import ssl
import string
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployed-stage-serves-mock-for-a-path-parameter-put-with-its-mapped-status"
GROUP = 'invoke'
SERVICES = ['apigateway']


# ===== helpers (self-contained) =====
def _tolerate_gone(fn):
    """Teardown that tolerates NotFoundException: the check deletes these itself on success."""
    def run_it():
        try:
            _throttle_retry(fn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    return run_it

def _throttle_retry(fn, *, attempts=4, base_delay=5.0, max_delay=15.0):
    """Call fn(), retrying only TooManyRequestsException (DeleteRestApi is rate limited per
    account) for at most about 35 s; the last error, or any other one, propagates."""
    delay = base_delay
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException" or i == attempts - 1:
                raise
            time.sleep(min(delay, max_delay))
            delay *= 2

def _not_found(fn, what, message):
    """fn() must raise NotFoundException with HTTP 404 and exactly ``message``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert got == ("NotFoundException", message), (
            f"{what}: expected ('NotFoundException', {message!r}), got {got!r}"
        )
        assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
        return
    raise AssertionError(f"{what}: expected NotFoundException, but the call SUCCEEDED: {result!r}")

def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    A REST API's only handle is a server-minted id, so
    the tag carries the sim2real marker too."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id

def _child(ctx, ag, api_id, path_part):
    """A child resource off root (registered for teardown)."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=path_part
    )["id"]
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_resource(restApiId=api_id, resourceId=resource_id)))
    return resource_id

def _deploy(ctx, ag, api_id):
    """CreateDeployment + CreateStage; returns (deployment_id, stage_name)."""
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage_name = f"s{_unique_token()}"
    kwargs = {
        "restApiId": api_id, "stageName": stage_name, "deploymentId": deployment_id,
        "tags": {"sim2real": CHECK},
    }
    ag.create_stage(**kwargs)
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_stage(restApiId=api_id, stageName=stage_name)))
    return deployment_id, stage_name

def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)

def _http(method, url, verify, body=None, headers=None):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify)) as resp:  # noqa: S310 - fixed http(s) scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode())
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode())
    except (urllib.error.URLError, OSError) as exc:
        raise AssertionError(
            f"DATAPLANE_UNIMPLEMENTED: the deployed stage at {url} did not answer: {exc!r}"
        ) from exc

def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a deployed stage, from ctx.rest_api_url."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"

def _poll_http(url, predicate, verify, *, method="GET", body=None, headers=None,
               timeout_s=40.0, interval_s=3.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds.

    A REST API deployment becomes servable on its stage asynchronously, so the first
    touch of a freshly (re-)deployed stage polls to a condition with a bounded
    deadline rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status, resp_headers, text = _http(method, url, verify, body=body, headers=headers)
        except AssertionError:
            # A connection error while the stage propagates is retried; the last one is raised
            # as DATAPLANE_UNIMPLEMENTED once the deadline passes.
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            continue
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=({status}, {text!r})"
            )
        time.sleep(interval_s)


def _body(text):
    """The response body parsed as JSON, or the raw text when it is not JSON."""
    try:
        return json.loads(text)
    except ValueError:
        return text


# ===== end helpers =====

def _mock_status_method(ag, api_id, resource_id, http_method, status, response_template):
    """A MOCK method whose request template selects ``status`` and whose only integration
    response (the default) maps that status with ``response_template``."""
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
        authorizationType="NONE", requestParameters={"method.request.path.orderId": True},
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, type="MOCK",
        requestTemplates={"application/json": f'{{"statusCode": {status}}}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode=str(status),
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode=str(status),
        selectionPattern="", responseTemplates={"application/json": response_template},
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed stage serves a PUT on a nested {orderId} resource with the MOCK method's non-200
    status and a body mapped from each request's own path parameter, query string and $context;
    after DeleteStage the URL stops serving and the stage is unreadable and unmutable."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    orders_id = _child(ctx, ag, api_id, "orders")
    item_id = ag.create_resource(restApiId=api_id, parentId=orders_id, pathPart="{orderId}")["id"]
    ctx.on_cleanup(_tolerate_gone(lambda: ag.delete_resource(restApiId=api_id, resourceId=item_id)))
    status_code = random.choice([201, 202, 203])
    template = (
        '{"orderId":"$input.params(\'orderId\')",'
        '"q":"$input.params(\'q\')",'
        '"stage":"$context.stage",'
        '"httpMethod":"$context.httpMethod",'
        '"resourcePath":"$context.resourcePath"}'
    )
    _mock_status_method(ag, api_id, item_id, "PUT", status_code, template)
    _, stage = _deploy(ctx, ag, api_id)

    order_a, order_b = f"ord{_unique_token(8)}", f"ord{_unique_token(8)}"
    query_a, query_b = _unique_token(6), _unique_token(6)
    put = {"method": "PUT", "body": b"{}", "headers": {"Content-Type": "application/json"}}
    url_a = _apigw_url(ctx, api_id, stage, f"/orders/{order_a}") + f"?q={query_a}"
    status, headers, text = _poll_http(
        url_a, lambda s, h, t: s == status_code, ctx.http_verify, **put,
        description=f"PUT {url_a} to serve the deployed MOCK integration",
    )
    assert headers.get("content-type", "").startswith("application/json"), (
        f"expected an application/json content-type, got {headers.get('content-type')!r}"
    )
    expected_a = {"orderId": order_a, "q": query_a, "stage": stage, "httpMethod": "PUT",
                  "resourcePath": "/orders/{orderId}"}
    assert json.loads(text) == expected_a, f"PUT {url_a}: expected {expected_a!r}, got {text!r}"

    url_b = _apigw_url(ctx, api_id, stage, f"/orders/{order_b}") + f"?q={query_b}"
    status_b, _, text_b = _http("PUT", url_b, ctx.http_verify, body=b"{}",
                                headers={"Content-Type": "application/json"})
    expected_b = dict(expected_a, orderId=order_b, q=query_b)
    assert (status_b, json.loads(text_b)) == (status_code, expected_b), (
        f"PUT {url_b}: expected ({status_code}, {expected_b!r}), got ({status_b}, {text_b!r})"
    )

    ag.delete_stage(restApiId=api_id, stageName=stage)
    _not_found(lambda: ag.get_stage(restApiId=api_id, stageName=stage), "GetStage on the deleted stage",
               "Invalid stage identifier specified")
    stage_names = [i.get("stageName") for i in ag.get_stages(restApiId=api_id).get("item", [])]
    assert stage not in stage_names, f"deleted stage still listed by GetStages: {stage_names!r}"
    _not_found(
        lambda: ag.update_stage(
            restApiId=api_id, stageName=stage,
            patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
        ),
        "UpdateStage on the deleted stage", "Invalid stage identifier specified",
    )
    # Stage removal propagates asynchronously; once the URL stops serving it answers Forbidden.
    gone = _poll_http(
        url_a, lambda s, h, t: s != status_code and order_a not in t, ctx.http_verify, **put,
        description=f"PUT {url_a} to stop serving after DeleteStage",
    )
    assert (gone[0], _body(gone[2])) == (403, {"message": "Forbidden"}), (
        f"PUT to the deleted stage: expected (403, {{'message': 'Forbidden'}}), got ({gone[0]}, {gone[2]!r})"
    )

    _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id))
    api_gone = f"Invalid API identifier specified {ctx.account}:{api_id}"
    _not_found(lambda: ag.get_rest_api(restApiId=api_id), "GetRestApi on the deleted API", api_gone)
    _not_found(lambda: ag.get_resource(restApiId=api_id, resourceId=item_id),
               "GetResource on the deleted API", "Invalid Resource identifier specified")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
