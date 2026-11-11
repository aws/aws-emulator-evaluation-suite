"""cfn-apigatewayv2-identity-readonly-ignored-writeonly-body-hidden-from-cloudcontrol."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-apigatewayv2-identity-readonly-ignored-writeonly-body-hidden-from-cloudcontrol"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudcontrol", "cloudformation"]

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}


def _poll(cf, stack_id: str, terminal: set, *, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::ApiGatewayV2::Api's Ref and read-only Fn::GetAtt attributes match API Gateway's
    own answer and ignore a template ApiEndpoint override; its write-only Body creates a real
    route but is absent from Cloud Control's model.
    """
    cf = ctx.client("cloudformation")
    apigw = ctx.client("apigatewayv2")
    cc = ctx.client("cloudcontrol")

    stack_name = ctx.unique_name("sim2real-behav-apigwid-")
    bogus_endpoint = "https://sim2real-bogus.example.com"
    openapi_body = {
        "openapi": "3.0.1",
        "info": {"title": "sim2real-behav-api", "version": "1.0"},
        "paths": {
            "/probe": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Api": {
                    "Type": "AWS::ApiGatewayV2::Api",
                    "Properties": {"Body": openapi_body, "ApiEndpoint": bogus_endpoint},
                },
            },
            "Outputs": {
                "ApiRef": {"Value": {"Ref": "Api"}},
                "ApiEndpointOut": {"Value": {"Fn::GetAtt": ["Api", "ApiEndpoint"]}},
                "ExecuteApiArnOut": {"Value": {"Fn::GetAtt": ["Api", "ExecuteApiArn"]}},
            },
        }
    )

    stack_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    status = _poll(cf, stack_id, _CREATE_TERMINAL)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cf.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    api_id = outputs["ApiRef"]
    getatt_endpoint = outputs["ApiEndpointOut"]
    getatt_execute_arn = outputs["ExecuteApiArnOut"]

    # Ref is the primary identifier, and API Gateway itself recognizes it as the api's own id.
    live = apigw.get_api(ApiId=api_id)
    assert live["ApiId"] == api_id, (
        f"API Gateway's own GetApi reports ApiId {live['ApiId']!r}, expected Ref {api_id!r}"
    )

    # Fn::GetAtt ApiEndpoint is the read-only attribute API Gateway itself computed, never the
    # template's override.
    assert getatt_endpoint == live["ApiEndpoint"], (
        f"Fn::GetAtt ApiEndpoint {getatt_endpoint!r} does not match API Gateway's own "
        f"ApiEndpoint {live['ApiEndpoint']!r}"
    )
    assert getatt_endpoint != bogus_endpoint, (
        f"Fn::GetAtt ApiEndpoint took the template's read-only override {bogus_endpoint!r}"
    )
    # The endpoint's leading host labels are the api id, the execute-api label and the region.
    parsed = urllib.parse.urlsplit(live["ApiEndpoint"])
    labels = tuple((parsed.hostname or "").split(".")[:3])
    assert labels == (api_id, "execute-api", ctx.region), (
        f"GetApi ApiEndpoint {live['ApiEndpoint']!r} does not carry the api id, execute-api and "
        f"the region as its leading host labels: {labels!r}"
    )

    # The Body's info.title names the api, and the Body's OpenAPI document makes it an HTTP api.
    assert (live["Name"], live["ProtocolType"]) == ("sim2real-behav-api", "HTTP"), (
        f"GetApi Name/ProtocolType {(live['Name'], live['ProtocolType'])!r} do not reflect the Body"
    )

    # Fn::GetAtt ExecuteApiArn follows API Gateway's own documented execute-api ARN form.
    expected_execute_arn = f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}"
    assert getatt_execute_arn == expected_execute_arn, (
        f"Fn::GetAtt ExecuteApiArn {getatt_execute_arn!r} does not match the documented "
        f"execute-api ARN {expected_execute_arn!r} for api {api_id!r}"
    )

    # The write-only Body reached API Gateway as a real route.
    routes = apigw.get_routes(ApiId=api_id)["Items"]
    assert [r["RouteKey"] for r in routes] == ["GET /probe"], (
        f"the write-only Body did not create the route GET /probe: {routes!r}"
    )

    # But Cloud Control's own resource model omits Body.
    cc_properties = json.loads(
        cc.get_resource(TypeName="AWS::ApiGatewayV2::Api", Identifier=api_id)[
            "ResourceDescription"
        ]["Properties"]
    )
    populated = (cc_properties.get("ApiId"), cc_properties.get("Name"), cc_properties.get("ApiEndpoint"))
    assert populated == (api_id, live["Name"], live["ApiEndpoint"]), (
        f"Cloud Control's model lacks the readable ApiId/Name/ApiEndpoint: {cc_properties!r}"
    )
    assert "Body" not in cc_properties, (
        f"Cloud Control's GetResource ResourceModel carries the write-only Body: {cc_properties!r}"
    )

    _delete_stack(cf, stack_id)
    code, message = _error(lambda: apigw.get_api(ApiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    expected_message = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == expected_message, (
        f"expected API Gateway's standard not-found message {expected_message!r}, got {message!r}"
    )


def _delete_stack(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll(cf, stack_id, _DELETE_TERMINAL)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} ended {status!r}, expected DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
