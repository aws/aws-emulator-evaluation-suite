"""create-route-nonexistent-api-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-route-nonexistent-api-fails"
GROUP = 'error-semantics'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRoute against a nonexistent ApiId fails with NotFoundException, and the bogus
    ApiId has no routes reachable either -- while the identical call shape against a real
    HTTP API succeeds and the created route is visible via an independent GetRoutes read."""
    agw = ctx.client("apigatewayv2")

    # Positive control: the identical call shape succeeds against a real API.
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-crnaf-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: agw.delete_api(ApiId=api_id)))
    agw.create_route(ApiId=api_id, RouteKey="GET /x")

    # Negative: the identical call against an ApiId that does not exist.
    bogus_api_id = "bogusapiid1"
    code, message = _error_code(lambda: agw.create_route(ApiId=bogus_api_id, RouteKey="GET /x"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}: {message!r}"
    expected_message = f"Invalid API identifier specified {ctx.account}:{bogus_api_id}"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the bogus ApiId has no routes reachable either.
    absent_code, absent_message = _error_code(lambda: agw.get_routes(ApiId=bogus_api_id))
    assert absent_code == "NotFoundException", (
        f"expected NotFoundException, got {absent_code!r}: {absent_message!r}"
    )
    expected_message = f"Invalid API identifier specified {ctx.account}:{bogus_api_id}"
    assert absent_message == expected_message, (
        f"expected the exact message {expected_message!r}, got {absent_message!r}"
    )

    # Terminal read: independent of the mutating CreateRoute call, at the real API.
    routes = agw.get_routes(ApiId=api_id)["Items"]
    assert any(r["RouteKey"] == "GET /x" for r in routes), (
        f"created route not visible via GetRoutes: {routes}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises.
    Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
