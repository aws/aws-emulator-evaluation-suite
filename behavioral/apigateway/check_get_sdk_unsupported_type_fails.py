"""get-sdk-unsupported-type-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sdk-unsupported-type-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSdk for an sdkType absent from GetSdkTypes fails BadRequestException, while a supported
    type on the same stage generates a real zip bundle (positive control)."""
    apigw = ctx.client("apigateway")
    api = _minimal_deployed_api(ctx)

    known_types = {item["id"] for item in apigw.get_sdk_types().get("items", [])}
    bogus_type = "totally-not-a-real-sdk-type"
    assert bogus_type not in known_types, (
        f"expected {bogus_type!r} to be absent from the enumerated sdk types, got {known_types!r}"
    )

    real_type = sorted(known_types)[0]
    type_detail = apigw.get_sdk_type(id=real_type)
    required_params = {
        prop["name"]: (prop.get("defaultValue") or "sim2real-behav-value")
        for prop in type_detail.get("configurationProperties", [])
        if prop.get("required")
    }
    sdk_kwargs = {"restApiId": api["id"], "stageName": api["stage"], "sdkType": real_type}
    if required_params:
        sdk_kwargs["parameters"] = required_params

    sdk = apigw.get_sdk(**sdk_kwargs)
    sdk_bytes = sdk["body"].read() if hasattr(sdk["body"], "read") else sdk["body"]
    assert len(sdk_bytes) > 100, (
        f"expected a real generated SDK bundle for supported type {real_type!r}, "
        f"got {len(sdk_bytes)} bytes"
    )
    assert sdk_bytes[:2] == b"PK", (
        f"expected the generated SDK for {real_type!r} to be a real zip archive "
        f"(PK magic), got header {sdk_bytes[:4]!r}"
    )

    code, message = _error(
        lambda: apigw.get_sdk(
            restApiId=api["id"], stageName=api["stage"], sdkType=bogus_type
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException requesting an unsupported sdkType, got {code!r}"
    )
    assert message == f"No SDK generator for type '{bogus_type}'", f"unexpected message: {message!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected an unsupported sdkType to be rejected, but it succeeded: {result!r}")


def _minimal_deployed_api(ctx) -> dict:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-sdk-api-"),
        tags={"sim2real": "get-sdk-unsupported-type-fails"},
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    return {"id": api_id, "stage": stage_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
