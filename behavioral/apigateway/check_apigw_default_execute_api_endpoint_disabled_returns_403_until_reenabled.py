"""apigw-default-execute-api-endpoint-disabled-returns-403-until-reenabled."""
from __future__ import annotations

import json
import random
import string
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "apigw-default-execute-api-endpoint-disabled-returns-403-until-reenabled"
GROUP = "deployments-stages"
SERVICES = ["apigateway"]

# Bounds how long the flag may take to reach / leave the execute-api edge. Stated, bounded,
# and a FAIL on expiry — never a sleep.
_PROPAGATION_S = 180.0


# ===== helpers (self-contained) =====
def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff.

    The apigateway control plane rate-limits mutating calls per account, so concurrent calls
    can surface as a throttle unrelated to the claim."""
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
    raise AssertionError(f"root ('/') resource not found on restApiId={api_id!r}")


def _create_api(ctx, ag, scenario):
    """A REGIONAL REST API registered for teardown; name, description and tag all carry
    the sim2real marker because the only handle is a server-minted id."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        description=f"sim2real {scenario}",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _http(method, url, body=None, headers=None, timeout=20):
    """HTTP request; returns (status, lowercased response headers, body text)."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed scheme
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as exc:
        return (exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()},
                exc.read().decode(errors="replace"))


def _apigw_url(ctx, api_id, stage, path=""):
    """Invoke URL for a path on a deployed stage."""
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _poll_http(url, predicate, *, method="GET", body=None, headers=None,
               timeout_s=_PROPAGATION_S, interval_s=5.0, description="stage response"):
    """Re-issue an HTTP request until predicate(status, headers, text) holds; RAISE on the
    deadline rather than returning the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        status, resp_headers, text = _http(method, url, body=body, headers=headers)
        if predicate(status, resp_headers, text):
            return status, resp_headers, text
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; "
                f"last=(status={status}, body={text[:200]!r})"
            )
        time.sleep(interval_s)
# ===== end helpers =====


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """`disableExecuteApiEndpoint=true` (after a redeploy) makes the `{id}.execute-api` hostname
    answer 403 for a stage that served 200, while GetStage and TestInvokeMethod show the API and
    method intact; clearing the flag restores the identical call to 200."""
    ag = ctx.client("apigateway")
    marker = f"sim2real-{_unique_token()}"

    api_id = _create_api(ctx, ag, "disable-execute-api-endpoint")
    root = _root_id(ag, api_id)
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=root, httpMethod="GET", authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200",
        selectionPattern="",
        responseTemplates={"application/json": '{"marker":"%s"}' % marker}))

    stage = f"s{_unique_token()}"
    first_deployment = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName=stage, deploymentId=first_deployment,
        tags={"sim2real": CHECK}))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName=stage)))

    url = _apigw_url(ctx, api_id, stage)

    # ---- beat 1: positive control on the default endpoint ------------------------------
    _poll_http(
        url, lambda s, h, t: s == 200 and marker in t,
        description=f"GET {url} to serve the deployed stage with marker {marker!r}",
    )
    before = ag.get_rest_api(restApiId=api_id)
    assert not before.get("disableExecuteApiEndpoint"), (
        f"precondition: a freshly created REST API must have the default endpoint ENABLED, "
        f"but GetRestApi reported disableExecuteApiEndpoint="
        f"{before.get('disableExecuteApiEndpoint')!r}"
    )

    # ---- beat 2: break exactly one thing ----------------------------------------------
    _retry_throttled(lambda: ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/disableExecuteApiEndpoint",
                          "value": "true"}]))
    disabled = ag.get_rest_api(restApiId=api_id)
    assert disabled.get("disableExecuteApiEndpoint") is True, (
        f"expected GetRestApi to report disableExecuteApiEndpoint=True after the patch, got "
        f"{disabled.get('disableExecuteApiEndpoint')!r}"
    )
    second_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=api_id, stageName=stage))["id"]
    assert second_deployment != first_deployment, (
        f"expected a NEW deployment id from the take-effect redeploy, got the first one "
        f"again: {second_deployment!r}"
    )

    # ---- beat 3: the specific refusal, held over three consecutive reads ---------------
    # The disable propagates across the edge, so a 403 can flap back to 200 until it settles.
    settle_deadline = time.monotonic() + _PROPAGATION_S
    while True:
        status, headers, text = _poll_http(
            url, lambda s, h, t: s == 403,
            description=(
                f"GET {url} to be refused with 403 once the default execute-api endpoint is "
                f"disabled and the API redeployed"
            ),
        )
        again = [_http("GET", url) for _ in range(3)]
        if all(s == 403 for s, _h, _t in again) or time.monotonic() >= settle_deadline:
            break
        time.sleep(2.0)
    assert status == 403, (
        f"expected 403 on the default execute-api endpoint after disabling it, got "
        f"{status} with body {text[:200]!r}"
    )
    assert marker not in text, (
        f"expected the refused response NOT to carry the integration marker {marker!r} — a "
        f"403 that still returns the body means the request reached the method; got "
        f"{text[:200]!r}"
    )
    # The refusal is graded on its body as well as its status.
    body = json.loads(text)
    assert body == {"message": "Forbidden"}, (
        f"expected the disabled default endpoint to answer the JSON body "
        f"{{'message': 'Forbidden'}}, got {body!r} (headers={headers!r})"
    )
    for attempt, (again_status, _h, again_text) in enumerate(again):
        assert again_status == 403 and marker not in again_text, (
            f"expected the 403 to be stable, but consecutive read {attempt + 1}/3 returned "
            f"status={again_status} body={again_text[:200]!r} within {_PROPAGATION_S}s — a refusal "
            f"that keeps flapping back to 200 is propagation, not enforcement"
        )
        assert json.loads(again_text) == {"message": "Forbidden"}, again_text

    # ---- beat 4: effect-absent / scope, via two other operations -----------------------
    live_stage = ag.get_stage(restApiId=api_id, stageName=stage)
    assert live_stage.get("deploymentId") == second_deployment, (
        f"the stage must still point at the redeployed snapshot {second_deployment!r} while "
        f"the default endpoint is refused, got {live_stage.get('deploymentId')!r} — the 403 "
        f"must not be a side effect of a broken stage"
    )
    simulated = ag.test_invoke_method(
        restApiId=api_id, resourceId=root, httpMethod="GET", pathWithQueryString="/")
    assert simulated.get("status") == 200, (
        f"expected TestInvokeMethod to still execute the method (status 200) while only the "
        f"execute-api hostname is disabled, got status={simulated.get('status')!r} body="
        f"{str(simulated.get('body'))[:200]!r}"
    )
    assert marker in str(simulated.get("body")), (
        f"expected TestInvokeMethod's body to carry the integration marker {marker!r}, "
        f"proving the method is intact and only the hostname is refused, got "
        f"{str(simulated.get('body'))[:200]!r}"
    )

    # ---- beat 5: restore, and the IDENTICAL call succeeds again -------------------------
    _retry_throttled(lambda: ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/disableExecuteApiEndpoint",
                          "value": "false"}]))
    reenabled = ag.get_rest_api(restApiId=api_id)
    assert not reenabled.get("disableExecuteApiEndpoint"), (
        f"expected GetRestApi to report the default endpoint re-enabled, got "
        f"disableExecuteApiEndpoint={reenabled.get('disableExecuteApiEndpoint')!r}"
    )
    third_deployment = _retry_throttled(
        lambda: ag.create_deployment(restApiId=api_id, stageName=stage))["id"]
    assert third_deployment not in (first_deployment, second_deployment), (
        f"expected a NEW deployment id for the restore redeploy, got {third_deployment!r}"
    )
    restored_status, _rh, restored_text = _poll_http(
        url, lambda s, h, t: s == 200 and marker in t,
        description=(
            f"GET {url} to serve 200 with marker {marker!r} again once "
            f"disableExecuteApiEndpoint is cleared and the API redeployed"
        ),
    )
    assert restored_status == 200 and marker in restored_text, (
        f"expected the identical GET to succeed again after re-enabling the default "
        f"endpoint, got {restored_status} with body {restored_text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
