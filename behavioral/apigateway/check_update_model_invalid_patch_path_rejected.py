"""update-model-invalid-patch-path-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-model-invalid-patch-path-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]

_SCHEMA = json.dumps({"title": "Thing", "type": "object", "properties": {"id": {"type": "string"}}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateModel rejects a patch on the immutable /name path with BadRequestException while
    a patch on the mutable /description path (positive control) succeeds and the model's
    identity/name is left completely untouched by the failed attempt."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": "update-model-invalid-patch-path-rejected"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    model_name = "Thing" + ctx.unique_name("").replace("-", "")[:8]
    apigw.create_model(
        restApiId=api_id, name=model_name, contentType="application/json", schema=_SCHEMA
    )

    # Positive control: a supported patch path succeeds.
    apigw.update_model(
        restApiId=api_id,
        modelName=model_name,
        patchOperations=[{"op": "replace", "path": "/description", "value": "updated-desc"}],
    )
    after_control = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert after_control["description"] == "updated-desc", (
        f"positive control: expected description 'updated-desc', got {after_control['description']!r}"
    )

    # Negative: attempting to rename the model via patch is not a supported path.
    err = _client_error(
        lambda: apigw.update_model(
            restApiId=api_id,
            modelName=model_name,
            patchOperations=[{"op": "replace", "path": "/name", "value": "RenamedThing"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "Invalid patch path  '/name' specified for op 'replace'. Must be one of: [/description, /schema]"
    ), f"expected the exact patch-path refusal message, got {err.get('Message')!r}"

    unchanged = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert unchanged["name"] == model_name, "model name must not change after rejected patch"
    assert unchanged["description"] == "updated-desc", "prior successful patch must remain intact"


def _client_error(fn):
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
