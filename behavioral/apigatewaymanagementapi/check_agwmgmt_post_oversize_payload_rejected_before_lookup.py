"""agwmgmt-post-oversize-payload-rejected-before-lookup."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agwmgmt-post-oversize-payload-rejected-before-lookup"
GROUP = "overly-permissive"
SERVICES = ["apigatewaymanagementapi"]

_WELL_FORMED_UNKNOWN = "Fabc1cWIPHcCJ7A="
#: Measured ceiling for PostToConnection's payload, and the `Data` blob's modelled length max.
_MAX_PAYLOAD_BYTES = 131072

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


class _UnexpectedSuccess(AssertionError):
    """The call the check expected to be REJECTED succeeded."""


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise _UnexpectedSuccess("the call succeeded but real AWS rejects it")


def _http_status(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise _UnexpectedSuccess("the call succeeded but real AWS rejects it")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _deploy_websocket_stage(ctx, stage="dev"):
    v2 = ctx.client("apigatewayv2")
    api = v2.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration = v2.create_integration(ApiId=api_id, IntegrationType="MOCK")["IntegrationId"]
    v2.create_route(ApiId=api_id, RouteKey="$connect", Target=f"integrations/{integration}")
    deployment = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )
    return api_id, stage, api["ApiEndpoint"]


def _management_client(ctx, api_endpoint, stage):
    """The @connections client for one API+stage."""
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


def _wait_management_ready(mgmt):
    return _poll_until(
        lambda: _error_code(lambda: mgmt.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN))[0],
        lambda code: code == "GoneException",
        timeout_s=120.0,
        interval_s=4.0,
        description="the deployed stage's @connections route reaching the connection store",
    )


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PostToConnection enforces its 131072-byte payload ceiling BEFORE it resolves the connection:
    one byte over, the same unknown id that otherwise answers GoneException (410) answers a bare
    HTTP 413 (Code '413') instead, so the two refusals are ordered and the ordering is observable.
    """
    _api_id, stage, api_endpoint = _deploy_websocket_stage(ctx)
    mgmt = _management_client(ctx, api_endpoint, stage)
    _wait_management_ready(mgmt)

    # full setup + the baseline: at the ceiling, the request reaches the connection store
    at_limit = _error_code(
        lambda: mgmt.post_to_connection(
            ConnectionId=_WELL_FORMED_UNKNOWN, Data=b"x" * _MAX_PAYLOAD_BYTES
        )
    )
    assert at_limit == ("GoneException", ""), (
        f"a {_MAX_PAYLOAD_BYTES}-byte payload to an unknown connection returned {at_limit!r}, "
        f"expected ('GoneException', '') — at the ceiling the size must be accepted and the "
        f"connection lookup must be what fails"
    )

    # break exactly one thing: one byte more
    over = _MAX_PAYLOAD_BYTES + 1
    code, message = _error_code(
        lambda: mgmt.post_to_connection(ConnectionId=_WELL_FORMED_UNKNOWN, Data=b"x" * over)
    )
    assert code == "413", (
        f"a {over}-byte payload returned error Code {code!r} (message {message!r}); real AWS "
        f"answers a bare HTTP 413 with no x-amzn-errortype header, which botocore surfaces as "
        f"the Code '413'. A 'GoneException' here means the connection was resolved BEFORE the "
        f"size was checked; a 'PayloadTooLargeException' means the model's declared error was "
        f"returned, which real AWS does not do"
    )
    status = _http_status(
        lambda: mgmt.post_to_connection(ConnectionId=_WELL_FORMED_UNKNOWN, Data=b"x" * over)
    )
    assert status == 413, (
        f"the oversize PostToConnection answered HTTP {status!r}, expected 413"
    )

    # the ordering is a property of the size, not of that particular id: a MALFORMED id, which
    # otherwise answers BadRequestException, also yields 413 once the payload is oversize
    malformed_oversize_code, malformed_oversize_message = _error_code(
        lambda: mgmt.post_to_connection(ConnectionId="x", Data=b"x" * over)
    )
    assert malformed_oversize_code == "413", (
        f"an oversize payload with a MALFORMED connection id returned "
        f"{(malformed_oversize_code, malformed_oversize_message)!r}; the payload check precedes "
        f"id validation too, so this must also be '413' rather than 'BadRequestException'"
    )

    # (c) the positive control: a small payload on the same client still reaches the store, and
    # the other two operations are unaffected, so the 413s were about the payload
    small = _error_code(
        lambda: mgmt.post_to_connection(ConnectionId=_WELL_FORMED_UNKNOWN, Data=b"hi")
    )
    assert small == ("GoneException", ""), (
        f"a 2-byte payload returned {small!r}, expected ('GoneException', '') — the oversize "
        f"rejections above would then not be about the payload at all"
    )
    assert _error_code(
        lambda: mgmt.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN)
    ) == ("GoneException", ""), "GetConnection stopped reaching the connection store"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
