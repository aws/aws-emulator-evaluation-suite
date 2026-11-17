"""get-deployments-nonexistent-api-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployments-nonexistent-api-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployments against an ApiId that does not exist fails NotFoundException, while the
    same call lists a real API's deployment."""
    agw = ctx.client("apigatewayv2")

    real_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-agwv2-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=real_id))

    bogus_id = "bogus-" + real_id
    code, message = _error(lambda: agw.get_deployments(ApiId=bogus_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent ApiId, got {code}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bogus_id}", (
        f"expected the exact invalid-API-identifier message for {bogus_id}, got {message!r}"
    )

    # Positive control: the same operation lists a real API's own deployment, so the
    # rejection above is about THIS id, not about GetDeployments being universally denied.
    integration_id = agw.create_integration(
        ApiId=real_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="https://example.com/sim2real",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(
        ApiId=real_id, RouteKey="GET /sim2real", Target=f"integrations/{integration_id}"
    )
    deployment_id = agw.create_deployment(ApiId=real_id)["DeploymentId"]

    items = agw.get_deployments(ApiId=real_id)["Items"]
    assert any(item["DeploymentId"] == deployment_id for item in items), (
        f"expected deployment {deployment_id!r} in GetDeployments for {real_id!r}, "
        f"got {[i['DeploymentId'] for i in items]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
