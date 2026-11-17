"""create-deployment-no-routes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-no-routes-rejected"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment on an HTTP API with no routes is refused with BadRequestException and
    mints no deployment; adding one route lets the identical call succeed.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-deploynoroutes-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    code, message = _error(lambda: agw.create_deployment(ApiId=api_id))
    assert code == "BadRequestException", (
        f"CreateDeployment with no routes: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == "Unable to deploy API because no valid routes exist in this API", (
        f"unexpected message {message!r}"
    )

    deployments = agw.get_deployments(ApiId=api_id)["Items"]
    assert deployments == [], (
        f"the refused CreateDeployment must mint no deployment, got {deployments!r}"
    )

    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="https://example.com/probe",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /probe", Target=f"integrations/{integration_id}")

    created = agw.create_deployment(ApiId=api_id)
    deployment_id = created["DeploymentId"]
    confirmed = agw.get_deployment(ApiId=api_id, DeploymentId=deployment_id)
    assert confirmed["DeploymentId"] == deployment_id, (
        f"a deployment created once the API has a route must read back, got {confirmed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
