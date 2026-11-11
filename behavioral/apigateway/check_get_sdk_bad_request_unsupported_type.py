"""get-sdk-bad-request-unsupported-type."""
from __future__ import annotations

import random
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sdk-bad-request-unsupported-type"
GROUP = 'overly-permissive'
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
        tags={"sim2real": CHECK},
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSdk with an unsupported sdkType fails BadRequestException instead of producing a bundle,
    while a supported type on the same stage generates a real zip (positive control)."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    _quick_stage(ag, api_id, "prod")

    # Positive control. Required config properties per sdkType are server-reported by
    # GetSdkType, not fixed in the model, so they are read rather than assumed.
    sdk_types = ag.get_sdk_types()["items"]
    assert sdk_types, "expected GetSdkTypes to enumerate at least one supported SDK type"
    chosen_type = sorted(t["id"] for t in sdk_types)[0]
    sdk_type_detail = ag.get_sdk_type(id=chosen_type)
    required_params = {
        prop["name"]: (prop.get("defaultValue") or "sim2real-behav-value")
        for prop in sdk_type_detail.get("configurationProperties", [])
        if prop.get("required")
    }
    sdk_kwargs = {"restApiId": api_id, "stageName": "prod", "sdkType": chosen_type}
    if required_params:
        sdk_kwargs["parameters"] = required_params
    sdk = ag.get_sdk(**sdk_kwargs)
    sdk_bytes = sdk["body"].read() if hasattr(sdk["body"], "read") else sdk["body"]
    assert sdk_bytes[:2] == b"PK", (
        f"the positive control ({chosen_type!r}) did not generate a real zip archive, got "
        f"header {sdk_bytes[:4]!r}"
    )

    code, message = _error(
        lambda: ag.get_sdk(
            restApiId=api_id, stageName="prod", sdkType="sim2real-not-a-real-sdktype"
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for an unsupported sdkType, got {code}"
    )
    assert message == "No SDK generator for type 'sim2real-not-a-real-sdktype'", (
        f"unexpected message: {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
