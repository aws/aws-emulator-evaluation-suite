"""rest-api-and-http-api-ids-never-collide."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rest-api-and-http-api-ids-never-collide"
GROUP = "cross-service-identity"
SERVICES = ["apigateway", "apigatewayv2"]

_N_HTTP = 2


def _retry_throttled(fn, *, attempts=4, base_delay=5.0):
    """Call fn(), retrying only TooManyRequestsException with jittered backoff."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(base_delay * (attempt + 1) + random.uniform(0, 0.5))


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """REST API ids (apigateway) and HTTP API ids (apigatewayv2) never collide: a REST API id
    resolves only through apigateway and an HTTP API id only through apigatewayv2, and the other
    service answers NotFoundException with its exact message."""
    ag = ctx.client("apigateway")
    agv2 = ctx.client("apigatewayv2")

    def _rest_teardown(rid):
        def _cleanup():
            try:
                _retry_throttled(lambda: ag.delete_rest_api(restApiId=rid))
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                    raise
        return _cleanup

    # One REST API: DeleteRestApi is limited to one request every 30 s per account.
    rid = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-xsvc-rest-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(_rest_teardown(rid))
    rest_ids = [rid]

    http_ids: list[str] = []
    for i in range(_N_HTTP):
        hid = _retry_throttled(lambda i=i: agv2.create_api(
            Name=ctx.unique_name(f"sim2real-behav-xsvc-http-{i}-"),
            ProtocolType="HTTP",
            Tags={"sim2real": CHECK},
        ))["ApiId"]
        ctx.on_cleanup(lambda hid=hid: _retry_throttled(lambda: agv2.delete_api(ApiId=hid)))
        http_ids.append(hid)
    assert len(set(http_ids)) == _N_HTTP, f"expected {_N_HTTP} distinct HTTP API ids, got {http_ids!r}"

    # Each REST API id resolves on apigateway and nowhere on apigatewayv2.
    for rid in rest_ids:
        got = ag.get_rest_api(restApiId=rid)
        assert got["id"] == rid, f"expected GetRestApi to resolve its own id {rid!r}, got {got['id']!r}"
        code, message = _error(lambda rid=rid: agv2.get_api(ApiId=rid))
        assert code == "NotFoundException", (
            f"expected apigatewayv2.GetApi on a REST API id {rid!r} to be NotFoundException, got {code!r}"
        )
        expected = f"Invalid API identifier specified {ctx.account}:{rid}"
        assert message == expected, f"expected {expected!r}, got {message!r}"

    # Each HTTP API id resolves on apigatewayv2 and nowhere on apigateway.
    for hid in http_ids:
        got = agv2.get_api(ApiId=hid)
        assert got["ApiId"] == hid, f"expected GetApi to resolve its own id {hid!r}, got {got['ApiId']!r}"
        code, message = _error(lambda hid=hid: ag.get_rest_api(restApiId=hid))
        assert code == "NotFoundException", (
            f"expected apigateway.GetRestApi on an HTTP API id {hid!r} to be NotFoundException, got {code!r}"
        )
        expected = f"Invalid API identifier specified {ctx.account}:{hid}"
        assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
