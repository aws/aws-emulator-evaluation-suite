"""delete-route-settings-nonexistent-stage-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-route-settings-nonexistent-stage-not-found"
GROUP = "stage-deploy"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_ROUTE_KEY = "GET /u"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRouteSettings against a stage name that does not exist fails NotFoundException,
    while the identical call for a real route key on a real stage removes the per-route override
    and the route reverts to the stage's default throttle settings."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(Name=ctx.unique_name("sim2real-behav-rsnf-"), ProtocolType="HTTP", Tags=TAGS)
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationUri="https://example.com/u",
        IntegrationMethod="GET", PayloadFormatVersion="1.0",
    )
    agw.create_route(ApiId=api_id, RouteKey=_ROUTE_KEY, Target=f"integrations/{integ['IntegrationId']}")
    dep_id = agw.create_deployment(ApiId=api_id)["DeploymentId"]
    stage_name = f"s{ctx.unique_name('sim2real-behav-')[-8:]}"
    agw.create_stage(
        ApiId=api_id, StageName=stage_name, DeploymentId=dep_id, AutoDeploy=False,
        RouteSettings={_ROUTE_KEY: {"ThrottlingBurstLimit": 7, "ThrottlingRateLimit": 3.0}},
    )
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName=stage_name))

    before = agw.get_stage(ApiId=api_id, StageName=stage_name)
    assert before.get("RouteSettings", {}).get(_ROUTE_KEY, {}).get("ThrottlingBurstLimit") == 7, (
        f"CreateStage did not persist the per-route override: {before.get('RouteSettings')!r}"
    )

    doomed_stage = f"d{ctx.unique_name('sim2real-behav-')[-8:]}"
    code, message = _error(
        lambda: agw.delete_route_settings(ApiId=api_id, StageName=doomed_stage, RouteKey=_ROUTE_KEY)
    )
    assert code == "NotFoundException", (
        f"DeleteRouteSettings on a nonexistent stage: expected NotFoundException, got {code}: {message!r}"
    )
    assert message == "Invalid stage identifier specified", (
        f"DeleteRouteSettings on a nonexistent stage: unexpected message {message!r}"
    )

    # Effect absent: the real stage's override is untouched by the refused call on the fake one.
    unaffected = agw.get_stage(ApiId=api_id, StageName=stage_name)
    assert unaffected.get("RouteSettings", {}).get(_ROUTE_KEY, {}).get("ThrottlingBurstLimit") == 7, (
        f"the real stage's route settings changed after a refused call on an unrelated stage: "
        f"{unaffected.get('RouteSettings')!r}"
    )

    # positive control: the same call on the real stage removes the override.
    agw.delete_route_settings(ApiId=api_id, StageName=stage_name, RouteKey=_ROUTE_KEY)
    after = agw.get_stage(ApiId=api_id, StageName=stage_name)
    assert _ROUTE_KEY not in after.get("RouteSettings", {}), (
        f"DeleteRouteSettings on the real stage did not remove the override: {after.get('RouteSettings')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
