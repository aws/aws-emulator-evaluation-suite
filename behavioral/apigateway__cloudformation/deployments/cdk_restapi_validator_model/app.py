#!/usr/bin/env python3
"""A RestApi whose one method is wired to a request validator and a JSON-schema model.

Context:
  stack_name, api_name -- identify the resources this check created
"""
import json

import aws_cdk as cdk
from aws_cdk import aws_apigateway as apigateway

app = cdk.App()
stack_name = app.node.try_get_context("stack_name")
api_name = app.node.try_get_context("api_name")

stack = cdk.Stack(app, stack_name, stack_name=stack_name)

# A REGIONAL API whose methods require SigV4: the stage is never anonymously invokable.
api = apigateway.RestApi(
    stack, "Api", rest_api_name=api_name,
    deploy_options=apigateway.StageOptions(stage_name="prod"),
    endpoint_configuration=apigateway.EndpointConfiguration(
        types=[apigateway.EndpointType.REGIONAL]),
    default_method_options=apigateway.MethodOptions(
        authorization_type=apigateway.AuthorizationType.IAM),
)
model = api.add_model(
    "ItemInput",
    model_name="ItemInput",
    content_type="application/json",
    schema=apigateway.JsonSchema(
        schema=apigateway.JsonSchemaVersion.DRAFT4,
        title="ItemInput",
        type=apigateway.JsonSchemaType.OBJECT,
        properties={"name": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING)},
        required=["name"],
    ),
)
validator = api.add_request_validator(
    "Validator", validate_request_body=True, validate_request_parameters=False,
)
items = api.root.add_resource("items")
items.add_method(
    "POST",
    apigateway.MockIntegration(
        passthrough_behavior=apigateway.PassthroughBehavior.NEVER,
        request_templates={"application/json": '{"statusCode": 200}'},
        integration_responses=[
            apigateway.IntegrationResponse(
                status_code="200",
                response_templates={"application/json": json.dumps({"message": "accepted"})},
            )
        ],
    ),
    method_responses=[apigateway.MethodResponse(status_code="200")],
    request_validator=validator,
    request_models={"application/json": model},
)

cdk.CfnOutput(stack, "RestApiId", value=api.rest_api_id)
cdk.CfnOutput(stack, "ItemsResourceId", value=items.resource_id)
app.synth()
