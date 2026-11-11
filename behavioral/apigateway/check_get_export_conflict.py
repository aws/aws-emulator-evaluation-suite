"""get-export-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-export-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because a target accepting a call real AWS refuses must not be
    reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "get-export-conflict"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetExport succeeds on a deployed stage (positive control) and fails with NotFoundException
    ("Invalid stage identifier specified") on a stage that was never deployed."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)

    root_id = next(
        r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")["id"]
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": "{}"},
    )

    deployed_stage = "live"
    ag.create_deployment(restApiId=api_id, stageName=deployed_stage)

    positive = ag.get_export(restApiId=api_id, stageName=deployed_stage, exportType="swagger")
    assert positive["body"].read(), (
        "positive control failed: GetExport on a real deployed stage returned no body — "
        "GetExport is not healthy on this API/account, so the rejection below would be untrustworthy"
    )

    code, message = _error(
        lambda: ag.get_export(
            restApiId=api_id, stageName="sim2real-no-such-stage", exportType="swagger"
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for GetExport against a never-deployed stage "
        f"(positive control on stage {deployed_stage!r} succeeded), got {code}"
    )
    assert message == "Invalid stage identifier specified", (
        f"unexpected NotFoundException message {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
