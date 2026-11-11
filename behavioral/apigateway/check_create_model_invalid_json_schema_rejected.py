"""create-model-invalid-json-schema-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-invalid-json-schema-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel with a schema body that is not valid JSON Schema is rejected rather than
    stored verbatim, while a well-formed JSON Schema on the same API succeeds."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"),
        tags={"sim2real": "create-model-invalid-json-schema-rejected"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    bad_model_name = "BadModel"
    code, message = _error(
        lambda: apigw.create_model(
            restApiId=api_id,
            name=bad_model_name,
            contentType="application/json",
            schema="{this is not json at all!!",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = (
        "Invalid model specified: Validation Result: warnings : [], "
        "errors : [Invalid model schema specified]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: no model with that name was persisted on the API.
    not_found_code, not_found_message = _error(
        lambda: apigw.get_model(restApiId=api_id, modelName=bad_model_name)
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for {bad_model_name}, got {not_found_code}"
    )
    expected = f"Invalid model name specified: {bad_model_name}"
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # positive control: a well-formed JSON Schema body for the same API succeeds and persists.
    good_model_name = "GoodModel"
    valid_schema = (
        '{"$schema": "http://json-schema.org/draft-04/schema#", '
        '"title": "GoodModel", "type": "object", '
        '"properties": {"id": {"type": "string"}}}'
    )
    apigw.create_model(
        restApiId=api_id,
        name=good_model_name,
        contentType="application/json",
        schema=valid_schema,
    )
    fetched = apigw.get_model(restApiId=api_id, modelName=good_model_name)
    assert fetched["name"] == good_model_name, f"expected name {good_model_name}, got {fetched['name']}"
    assert "title" in fetched["schema"], f"expected 'title' in persisted schema, got {fetched['schema']}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
