"""import-rest-api-resolves-aws-pseudo-parameters-and-reresolves-on-overwrite."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "import-rest-api-resolves-aws-pseudo-parameters-and-reresolves-on-overwrite"
GROUP = "import-export"
SERVICES = ["apigateway"]


def _variable_resource_id(ag, api_id):
    """The id of the single '/variable' resource, which is recreated by every import."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/variable":
            return item["id"]
    raise RuntimeError("/variable resource not found")


def _doc(title, role_arn, templated_value):
    """A Swagger document whose AWS integration embeds the ${AWS::...} pseudo-parameters
    ImportRestApi is expected to resolve against the account doing the import."""
    return {
        "swagger": "2.0",
        "info": {"title": title, "version": "1.0"},
        "basePath": "/",
        "schemes": ["https"],
        "paths": {
            "/variable": {
                "post": {
                    "responses": {"200": {"description": "OK"}},
                    "x-amazon-apigateway-integration": {
                        "type": "AWS",
                        "httpMethod": "POST",
                        "uri": "arn:aws:apigateway:${AWS::Region}:states:action/StartExecution",
                        "credentials": role_arn,
                        "requestTemplates": {"application/json": f'{{"value":"{templated_value}"}}'},
                        "requestParameters": {
                            "integration.request.header.X-Region": "'${AWS::Region}'"
                        },
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
        "x-amazon-apigateway-gateway-responses": {
            "UNAUTHORIZED": {
                "responseTemplates": {"application/json": '{"account":"${AWS::AccountId}"}'}
            }
        },
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportRestApi stores ${AWS::Region} / ${AWS::AccountId} in integration and gateway-response
    fields resolved to the importing account/region, and PutRestApi(mode=overwrite) with a different
    pseudo-parameter re-resolves it instead of keeping the first import's value."""
    ag = ctx.client("apigateway")
    title = ctx.unique_name("sim2real-behav-apigw-variable-")
    # The integration is never invoked, so the credentials role is only stored, never assumed:
    # a name this check owns, in the caller's account, with no IAM resource behind it.
    role_arn = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-behav-apigw-var-role-')}"

    imported = ag.import_rest_api(body=json.dumps(_doc(title, role_arn, "${AWS::Region}")).encode())
    api_id = imported["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    ag.tag_resource(resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}",
                    tags={"sim2real": CHECK})

    resource_id = _variable_resource_id(ag, api_id)
    integration = ag.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="POST")
    assert integration.get("uri") == f"arn:aws:apigateway:{ctx.region}:states:action/StartExecution", (
        f"expected ${{AWS::Region}} resolved in the integration uri for region {ctx.region!r}, "
        f"got {integration.get('uri')!r}"
    )
    assert integration["requestTemplates"]["application/json"] == f'{{"value":"{ctx.region}"}}', (
        f"expected the request template's ${{AWS::Region}} resolved to {ctx.region!r}, got "
        f"{integration.get('requestTemplates')!r}"
    )
    assert integration["requestParameters"][
        "integration.request.header.X-Region"
    ] == f"'{ctx.region}'", (
        f"expected the request parameter's ${{AWS::Region}} resolved to {ctx.region!r}, got "
        f"{integration.get('requestParameters')!r}"
    )

    gateway_response = ag.get_gateway_response(restApiId=api_id, responseType="UNAUTHORIZED")
    assert gateway_response["responseTemplates"]["application/json"] == (
        f'{{"account":"{ctx.account}"}}'
    ), (
        f"expected ${{AWS::AccountId}} resolved to {ctx.account!r} in the UNAUTHORIZED gateway "
        f"response template, got {gateway_response.get('responseTemplates')!r}"
    )

    # Overwrite with the SAME path but a DIFFERENT pseudo-parameter in the template --
    # the resolution must track the new document, not echo the first import's value.
    ag.put_rest_api(
        restApiId=api_id, mode="overwrite",
        body=json.dumps(_doc(title, role_arn, "${AWS::AccountId}")).encode(),
    )
    resource_id_after = _variable_resource_id(ag, api_id)
    integration_after = ag.get_integration(
        restApiId=api_id, resourceId=resource_id_after, httpMethod="POST"
    )
    assert integration_after["requestTemplates"]["application/json"] == (
        f'{{"value":"{ctx.account}"}}'
    ), (
        f"expected the re-imported template's ${{AWS::AccountId}} resolved to {ctx.account!r} "
        f"after mode=overwrite, got {integration_after.get('requestTemplates')!r} -- a stale "
        f"first-import resolution would still show {ctx.region!r} here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
