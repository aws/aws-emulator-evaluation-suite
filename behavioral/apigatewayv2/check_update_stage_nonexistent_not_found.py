"""update-stage-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stage-nonexistent-not-found"
GROUP = "stage-deploy"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStage on a stage name that was deleted fails NotFoundException, while the identical
    call on a sibling stage of the same API still succeeds; a second DeleteStage on the dead name
    also fails NotFoundException rather than succeeding again."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(Name=ctx.unique_name("sim2real-behav-stagenf-"), ProtocolType="HTTP", Tags=TAGS)
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationUri="https://example.com/u",
        IntegrationMethod="GET", PayloadFormatVersion="1.0",
    )
    agw.create_route(ApiId=api_id, RouteKey="GET /u", Target=f"integrations/{integ['IntegrationId']}")
    dep_id = agw.create_deployment(ApiId=api_id)["DeploymentId"]

    sibling_name = f"s{ctx.unique_name('sim2real-behav-')[-8:]}"
    agw.create_stage(ApiId=api_id, StageName=sibling_name, DeploymentId=dep_id, AutoDeploy=False)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName=sibling_name))

    doomed_name = f"d{ctx.unique_name('sim2real-behav-')[-8:]}"
    agw.create_stage(ApiId=api_id, StageName=doomed_name, DeploymentId=dep_id, AutoDeploy=False)
    agw.delete_stage(ApiId=api_id, StageName=doomed_name)

    code, message = _error(
        lambda: agw.update_stage(ApiId=api_id, StageName=doomed_name, AutoDeploy=True)
    )
    assert code == "NotFoundException", (
        f"UpdateStage on a deleted stage: expected NotFoundException, got {code}: {message!r}"
    )
    assert message == "Invalid stage identifier specified", (
        f"UpdateStage on a deleted stage: unexpected message {message!r}"
    )

    second_code, second_message = _error(
        lambda: agw.delete_stage(ApiId=api_id, StageName=doomed_name)
    )
    assert second_code == "NotFoundException", (
        f"second DeleteStage on the dead name: expected NotFoundException, got {second_code}: "
        f"{second_message!r}"
    )
    assert second_message == "Invalid stage identifier specified", (
        f"second DeleteStage on the dead name: unexpected message {second_message!r}"
    )

    # positive control: the sibling stage is unaffected by its sibling's death.
    res = agw.update_stage(ApiId=api_id, StageName=sibling_name, AutoDeploy=True)
    assert res.get("AutoDeploy") is True, (
        f"UpdateStage on the live sibling stage did not take effect: {res.get('AutoDeploy')!r}"
    )
    fetched = agw.get_stage(ApiId=api_id, StageName=sibling_name)
    assert fetched.get("AutoDeploy") is True, (
        f"GetStage on the live sibling stage does not reflect the update: {fetched.get('AutoDeploy')!r}"
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
