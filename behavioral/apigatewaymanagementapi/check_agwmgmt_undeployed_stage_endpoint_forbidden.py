"""agwmgmt-undeployed-stage-endpoint-forbidden."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agwmgmt-undeployed-stage-endpoint-forbidden"
GROUP = "overly-permissive"
SERVICES = ["apigatewaymanagementapi"]

_WELL_FORMED_UNKNOWN = "Fabc1cWIPHcCJ7A="

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


class _UnexpectedSuccess(AssertionError):
    """The call the check expected to be REJECTED succeeded."""


def _error_of(fn):
    """The (code, message) of the error ``fn`` raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
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
    return ctx.client(
        "apigatewaymanagementapi",
        endpoint_url=ctx.stage_url(api_endpoint, stage, management=True),
        config=Config(retries={"max_attempts": 1}),
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The management endpoint's STAGE segment is authoritative: @connections on an undeployed
    stage name answers ForbiddenException (403) without reaching the connection store, while the
    identical request on the deployed stage of the SAME API answers GoneException (410)."""
    api_id, deployed, api_endpoint = _deploy_websocket_stage(ctx)
    mgmt = _management_client(ctx, api_endpoint, deployed)

    # full setup: establish that the deployed stage reaches the connection store, which is also
    # the readiness condition — before propagation the deployed stage 403s exactly like the
    # undeployed one, and asserting the 403 first would be vacuous.
    _poll_until(
        lambda: _error_of(lambda: mgmt.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN)),
        lambda got: got[0] == "GoneException",
        timeout_s=120.0,
        interval_s=4.0,
        description=(
            f"the deployed stage {deployed!r} reaching the connection store (GoneException for "
            f"an unknown id)"
        ),
    )

    # break exactly one thing: the stage segment of the endpoint
    undeployed = _management_client(ctx, api_endpoint, "sim2realnostage")
    observed = {
        "GetConnection": _error_of(
            lambda: undeployed.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN)
        ),
        "PostToConnection": _error_of(
            lambda: undeployed.post_to_connection(
                ConnectionId=_WELL_FORMED_UNKNOWN, Data=b"hi"
            )
        ),
        "DeleteConnection": _error_of(
            lambda: undeployed.delete_connection(ConnectionId=_WELL_FORMED_UNKNOWN)
        ),
    }
    for got in observed.values():
        assert got == ("ForbiddenException", "Forbidden"), (
            f"the undeployed-stage endpoint returned {observed!r}; real AWS returns "
            f"ForbiddenException (HTTP 403 'Forbidden') for all three operations. A GoneException "
            f"means the stage segment was ignored and the request reached the connection store "
            f"anyway"
        )

    # (b) the effect is absent: the deployed stage's view of the API is unchanged, and the
    # rejected calls created nothing — the API still has exactly the one stage it was given
    stages = []
    token = None
    v2 = ctx.client("apigatewayv2")
    while True:
        kwargs = {"ApiId": api_id, "MaxResults": "25"}
        if token is not None:
            kwargs["NextToken"] = token
        page = v2.get_stages(**kwargs)
        stages.extend(s["StageName"] for s in page.get("Items", []))
        token = page.get("NextToken")
        if token is None:
            break
    assert stages == [deployed], (
        f"the API's stages are {stages!r}; addressing an undeployed stage must not create one"
    )

    # (c) the positive control: the deployed stage still answers from the connection store
    control = _error_of(lambda: mgmt.get_connection(ConnectionId=_WELL_FORMED_UNKNOWN))
    assert control == ("GoneException", ""), (
        f"the deployed stage {deployed!r} now returns {control!r}; the 403s above would then be "
        f"about the API rather than about the stage segment"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
