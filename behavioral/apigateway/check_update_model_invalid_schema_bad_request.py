"""update-model-invalid-schema-bad-request."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-model-invalid-schema-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateModel rejects a malformed schema patch with BadRequestException, keeping the schema.
    A well-formed schema patch succeeds first; a deleted model reads and patches as NotFound."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "TestModel" + "".join(c for c in ctx.unique_name("x") if c.isalnum())[-10:]
    original_schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {"id": {"type": "string"}},
        }
    )
    apigw.create_model(
        restApiId=api_id, name=model_name, contentType="application/json", schema=original_schema
    )

    # Positive control: a well-formed schema patch on this same model succeeds.
    control_schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": model_name,
            "type": "object",
            "properties": {"id": {"type": "string"}, "note": {"type": "string"}},
        }
    )
    apigw.update_model(
        restApiId=api_id,
        modelName=model_name,
        patchOperations=[{"op": "replace", "path": "/schema", "value": control_schema}],
    )
    after_control = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert json.loads(after_control["schema"]) == json.loads(control_schema), (
        f"positive control patch did not take effect: {after_control['schema']!r}"
    )

    err = _client_error(
        lambda: apigw.update_model(
            restApiId=api_id,
            modelName=model_name,
            patchOperations=[{"op": "replace", "path": "/schema", "value": "{this is not valid json"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "Invalid model specified: Validation Result: warnings : [], errors : [Invalid model schema specified]"
    ), f"expected the exact invalid-schema refusal message, got {err.get('Message')!r}"

    got = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert json.loads(got["schema"]) == json.loads(control_schema), (
        f"schema must remain at the last good value {control_schema!r} after the rejected "
        f"patch, got {got['schema']!r}"
    )

    apigw.delete_model(restApiId=api_id, modelName=model_name)

    not_found_err = _client_error(
        lambda: apigw.get_model(restApiId=api_id, modelName=model_name)
    )
    assert not_found_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException reading a deleted model, got {not_found_err.get('Code')!r}"
    )
    assert not_found_err.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message reading a deleted model, got {not_found_err.get('Message')!r}"
    )

    mutate_dead_err = _client_error(
        lambda: apigw.update_model(
            restApiId=api_id,
            modelName=model_name,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert mutate_dead_err.get("Code") == "NotFoundException", (
        f"expected NotFoundException patching a deleted model, got {mutate_dead_err.get('Code')!r}"
    )
    assert mutate_dead_err.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message patching a deleted model, got {mutate_dead_err.get('Message')!r}"
    )

    remaining_names = {m["name"] for m in apigw.get_models(restApiId=api_id)["items"]}
    assert model_name not in remaining_names, f"{model_name} still listed after delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
