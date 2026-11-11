"""get-sdk-generates-artifact-for-supported-types."""
from __future__ import annotations

import random
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sdk-generates-artifact-for-supported-types"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "get-sdk-generates-artifact-for-supported-types"},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _quick_stage(ag, api_id, stage_name="prod"):
    """Wire a minimal MOCK method, deployment and stage on api_id; return the deploymentId."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=f"r{_unique_token()}"
    )["id"]
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    return deployment_id


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSdk generates a zip bundle for a type listed by GetSdkTypes and described by GetSdkType,
    while a made-up sdkType is rejected by GetSdkType (NotFound) and GetSdk (BadRequest)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    _quick_stage(ag, api_id, "prod")

    sdk_types = ag.get_sdk_types()["items"]
    assert sdk_types, "expected GetSdkTypes to enumerate at least one supported SDK type"
    supported_ids = {t["id"] for t in sdk_types}
    # `javascript`/`ruby` need no sdkType-specific parameters; use whichever is enumerated.
    no_extra_param_ids = supported_ids & {"javascript", "ruby"}
    assert no_extra_param_ids, (
        f"expected at least one no-extra-config sdkType ('javascript' or 'ruby') among the "
        f"enumerated supported sdkTypes, got {supported_ids!r}"
    )
    chosen_type = sorted(no_extra_param_ids)[0]

    sdk_type_detail = ag.get_sdk_type(id=chosen_type)
    assert sdk_type_detail["id"] == chosen_type
    assert "configurationProperties" in sdk_type_detail

    required_params = {
        prop["name"]: (prop.get("defaultValue") or "sim2real-behav-value")
        for prop in sdk_type_detail.get("configurationProperties", [])
        if prop.get("required")
    }
    sdk_kwargs = {"restApiId": api_id, "stageName": "prod", "sdkType": chosen_type}
    if required_params:
        sdk_kwargs["parameters"] = required_params

    sdk = ag.get_sdk(**sdk_kwargs)
    assert sdk.get("contentType"), f"expected a contentType on the generated SDK, got {sdk!r}"
    sdk_bytes = sdk["body"].read() if hasattr(sdk["body"], "read") else sdk["body"]
    assert len(sdk_bytes) > 100, f"expected a non-trivial generated SDK bundle, got {len(sdk_bytes)} bytes"
    assert sdk_bytes[:2] == b"PK", (
        f"expected the generated SDK to be a real zip archive (PK magic), got header {sdk_bytes[:4]!r}"
    )

    bogus_type_code, bogus_type_message = _error(lambda: ag.get_sdk_type(id="sim2real-bogus-sdktype"))
    assert bogus_type_code == "NotFoundException", (
        f"expected NotFoundException describing an unsupported sdkType id, got {bogus_type_code}"
    )
    assert bogus_type_message == "No SDK generator for 'sim2real-bogus-sdktype'", (
        f"unexpected GetSdkType message: {bogus_type_message!r}"
    )

    bogus_sdk_code, bogus_sdk_message = _error(
        lambda: ag.get_sdk(restApiId=api_id, stageName="prod", sdkType="sim2real-bogus-sdktype")
    )
    assert bogus_sdk_code == "BadRequestException", (
        f"expected BadRequestException generating an SDK for an unsupported sdkType, got {bogus_sdk_code}"
    )
    assert bogus_sdk_message == "No SDK generator for type 'sim2real-bogus-sdktype'", (
        f"unexpected GetSdk message: {bogus_sdk_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
