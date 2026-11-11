"""delete-api-removes-its-routes-integrations-and-stages."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-api-removes-its-routes-integrations-and-stages"
GROUP = "lifecycle"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApi removes the API's children with it: its route, integration, stage and deployment
    all read NotFound afterwards, while a sibling API's identical children are untouched.
    """
    agw = ctx.client("apigatewayv2")
    built = []
    for _ in range(2):
        api_id = agw.create_api(
            Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
        )["ApiId"]
        ctx.on_cleanup(lambda a=api_id: _delete_if_present(agw, a))
        integ = agw.create_integration(
            ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationMethod="GET",
            IntegrationUri="https://example.com/", PayloadFormatVersion="1.0",
        )["IntegrationId"]
        route = agw.create_route(
            ApiId=api_id, RouteKey="GET /items", Target=f"integrations/{integ}"
        )["RouteId"]
        agw.create_stage(ApiId=api_id, StageName="prod")
        deployment = agw.create_deployment(ApiId=api_id, StageName="prod")["DeploymentId"]
        built.append((api_id, integ, route, deployment))

    (api_id, integ, route, deployment), sibling = built
    agw.delete_api(ApiId=api_id)
    reads = {
        "GetApi": lambda: agw.get_api(ApiId=api_id),
        "GetRoute": lambda: agw.get_route(ApiId=api_id, RouteId=route),
        "GetIntegration": lambda: agw.get_integration(ApiId=api_id, IntegrationId=integ),
        "GetStage": lambda: agw.get_stage(ApiId=api_id, StageName="prod"),
    }
    for what, read in reads.items():
        code, _ = _error(read)  # the message names the account, so only the code is asserted
        assert code == "NotFoundException", f"{what} after DeleteApi: got {code!r}"
    code, message = _error(lambda: agw.get_deployment(ApiId=api_id, DeploymentId=deployment))
    assert code == "NotFoundException", f"GetDeployment after DeleteApi: got {code!r}"
    assert message == "Invalid Deployment identifier specified", f"unexpected message {message!r}"

    s_api, s_integ, s_route, s_deployment = sibling
    assert agw.get_route(ApiId=s_api, RouteId=s_route)["RouteKey"] == "GET /items", "sibling route"
    assert agw.get_integration(ApiId=s_api, IntegrationId=s_integ)["IntegrationId"] == s_integ, (
        "the sibling API's integration was affected"
    )
    stage = agw.get_stage(ApiId=s_api, StageName="prod")
    assert stage.get("DeploymentId") == s_deployment, f"the sibling stage changed: {stage!r}"


def _delete_if_present(agw, api_id):
    try:
        agw.delete_api(ApiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

