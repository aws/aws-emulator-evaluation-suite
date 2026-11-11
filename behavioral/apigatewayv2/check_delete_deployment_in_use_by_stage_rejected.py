"""delete-deployment-in-use-by-stage-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-deployment-in-use-by-stage-rejected"
GROUP = 'stage-deploy'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _deployment_ids(agw, api_id):
    ids, token = set(), None
    while True:
        kw = {"ApiId": api_id, "NextToken": token} if token else {"ApiId": api_id}
        page = agw.get_deployments(**kw)
        ids.update(d["DeploymentId"] for d in page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            return ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeployment of the deployment a stage is bound to is refused and changes nothing;
    the same call on an unreferenced deployment of the same API succeeds.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri="https://example.com/d",
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /d", Target=f"integrations/{integ_id}")
    d1 = agw.create_deployment(ApiId=api_id, Description="bound")["DeploymentId"]
    d2 = agw.create_deployment(ApiId=api_id, Description="unreferenced")["DeploymentId"]
    agw.create_stage(ApiId=api_id, StageName="live", DeploymentId=d1, AutoDeploy=False, Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_stage(ApiId=api_id, StageName="live"))
    assert {d1, d2} <= _deployment_ids(agw, api_id), "GetDeployments must list both deployments"

    code, message = _error(lambda: agw.delete_deployment(ApiId=api_id, DeploymentId=d1))
    assert code == "BadRequestException", (
        f"deleting the deployment stage 'live' is bound to: expected BadRequestException, "
        f"got {code}: {message!r}"
    )
    expected = "Active stages pointing to this deployment must be moved or deleted"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    assert d1 in _deployment_ids(agw, api_id), "the refused DeleteDeployment removed the deployment"
    assert agw.get_stage(ApiId=api_id, StageName="live").get("DeploymentId") == d1, (
        "the refused DeleteDeployment changed the stage's DeploymentId"
    )

    agw.delete_deployment(ApiId=api_id, DeploymentId=d2)
    ids = _deployment_ids(agw, api_id)
    assert d2 not in ids, "the unreferenced deployment is still listed after DeleteDeployment"
    assert d1 in ids, "deleting the unreferenced deployment removed the bound one too"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
