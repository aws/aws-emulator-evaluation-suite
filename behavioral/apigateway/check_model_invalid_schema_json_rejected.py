"""model-invalid-schema-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invalid-schema-json-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel with a malformed JSON schema string is rejected and never persisted."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    bad_model_name = ctx.unique_name("BadModel").replace("-", "")
    malformed_schema = '{"type": "object", "properties": {"a": }'  # invalid JSON

    code, message = _error(
        lambda: apigw.create_model(
            restApiId=api_id,
            name=bad_model_name,
            contentType="application/json",
            schema=malformed_schema,
        )
    )
    assert code == "BadRequestException", code
    assert message == (
        "Invalid model specified: Validation Result: warnings : [], errors : [Invalid model schema specified]"
    ), message

    # Effect absent: the malformed model was never created, on two independent reads.
    existing_names = {m["name"] for m in apigw.get_models(restApiId=api_id)["items"]}
    assert bad_model_name not in existing_names, existing_names

    not_found_code, not_found_message = _error(
        lambda: apigw.get_model(restApiId=api_id, modelName=bad_model_name)
    )
    assert not_found_code == "NotFoundException", not_found_code
    assert not_found_message == f"Invalid model name specified: {bad_model_name}", not_found_message

    # Positive control: a well-formed model on the same API succeeds and is retrievable.
    good_model_name = ctx.unique_name("GoodModel").replace("-", "")
    valid_schema = '{"$schema":"http://json-schema.org/draft-04/schema#","title":"Valid","type":"object"}'
    apigw.create_model(
        restApiId=api_id, name=good_model_name, contentType="application/json", schema=valid_schema
    )
    ctx.on_cleanup(lambda: apigw.delete_model(restApiId=api_id, modelName=good_model_name))
    got = apigw.get_model(restApiId=api_id, modelName=good_model_name)
    assert json.loads(got["schema"]) == json.loads(valid_schema), got["schema"]


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
