"""agwmgmt-malformed-connection-id-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agwmgmt-malformed-connection-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigatewaymanagementapi"]

#: A well-formed connection id that no live socket owns. Base64 of 11 bytes, the shape API
#: Gateway mints; measured to reach the connection store and answer GoneException.
_WELL_FORMED_UNKNOWN = "Fabc1cWIPHcCJ7A="

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
    """A deployed WEBSOCKET API and stage, cleanup registered.

    Returns (api_id, stage, api_endpoint).
    """
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
    v2.create_route(
        ApiId=api_id, RouteKey="$connect", Target=f"integrations/{integration}"
    )
    deployment = v2.create_deployment(ApiId=api_id)["DeploymentId"]
    v2.create_stage(ApiId=api_id, StageName=stage, DeploymentId=deployment)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=stage)
    )
    return api_id, stage, api["ApiEndpoint"]


def _management_client(ctx, api_endpoint, stage):
    """The @connections client for one API+stage.

    The management API has no regional host: `execute-api.<region>.amazonaws.com` (what botocore
    resolves for this service) does not resolve in DNS at all, so the endpoint is always the API's
    published ApiEndpoint, with wss as https, plus the stage:
    `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>`.
    """
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


def _wait_management_ready(mgmt):
    """Poll until the deployed stage's @connections route answers the connection store.

    GoneException for a well-formed unknown id is the readiness condition. Before the stage has
    propagated the same call answers ForbiddenException, so this distinguishes "not deployed
    yet" from the validation behaviour under test rather than sleeping a guessed interval.
    """
    return _poll_until(
        lambda: _error_code(lambda: mgmt.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN))[0],
        lambda code: code == "GoneException",
        timeout_s=120.0,
        interval_s=4.0,
        description="the deployed stage's @connections route reaching the connection store",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed connection id is refused with BadRequestException (400) before the connection store
    is consulted, on GetConnection, PostToConnection and DeleteConnection alike; a well-formed but
    unknown id reaches the store instead and gets GoneException (410) — neither code is modelled.
    """
    _api_id, stage, api_endpoint = _deploy_websocket_stage(ctx)
    mgmt = _management_client(ctx, api_endpoint, stage)
    _wait_management_ready(mgmt)

    # break exactly one thing: the id's SHAPE, over four distinct malformations
    malformed = {
        "single-char": "x",
        "not-base64": "not base64!!",
        "unpadded": "Fabc1cWIPHcCJ7A",
        "overlong": "A" * 200,
    }
    observed = {
        label: _error_code(lambda cid=cid: mgmt.get_connection(ConnectionId=cid))
        for label, cid in malformed.items()
    }
    expected = {
        label: ("BadRequestException", f"Invalid connectionId: {cid}")
        for label, cid in malformed.items()
    }
    assert observed == expected, (
        f"GetConnection returned {observed!r} for malformed connection ids; real AWS returns "
        f"{expected!r}. A GoneException here means the id reached the connection store, which "
        f"is exactly the over-permissiveness this check exists to catch"
    )

    # the same malformation is refused on the other two operations, so it is the id and not the
    # operation that decides
    assert _error_code(
        lambda: mgmt.post_to_connection(ConnectionId="x", Data=b"hi")
    ) == ("BadRequestException", "Invalid connectionId: x"), (
        "PostToConnection accepted a malformed connection id"
    )
    assert _error_code(
        lambda: mgmt.delete_connection(ConnectionId="x")
    ) == ("BadRequestException", "Invalid connectionId: x"), (
        "DeleteConnection accepted a malformed connection id"
    )

    # (c) the positive control: the well-formed id DOES reach the connection store
    control = _error_code(
        lambda: mgmt.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN)
    )
    assert control == ("GoneException", ""), (
        f"a well-formed but unknown connection id returned {control!r}, expected "
        f"('GoneException', '') — without that the BadRequestExceptions above could just be "
        f"a blanket refusal of every id"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
