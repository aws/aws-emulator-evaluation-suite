"""op-contract-createModel."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-createModel"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel echoes name/contentType/schema on success; a duplicate name is rejected with
    ConflictException and no second model is created; once the conflicting model is deleted, the
    identical create succeeds again."""
    apigw = ctx.client("apigateway")
    api_id, _root_id = _create_rest_api(ctx)

    model_name = "WidgetModel"
    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "title": model_name,
        "type": "object",
        "properties": {"id": {"type": "string"}},
    }
    created = apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=json.dumps(schema),
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_model(restApiId=api_id, modelName=model_name))
    )
    assert created["name"] == model_name, f"expected created name {model_name!r}, got {created['name']!r}"
    assert created["contentType"] == "application/json", (
        f"expected contentType 'application/json', got {created['contentType']!r}"
    )
    created_title = json.loads(created["schema"])["title"]
    assert created_title == model_name, f"expected echoed schema title {model_name!r}, got {created_title!r}"

    fetched = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert fetched["id"] == created["id"], f"expected get_model id {created['id']!r}, got {fetched['id']!r}"
    fetched_id_type = json.loads(fetched["schema"])["properties"]["id"]["type"]
    assert fetched_id_type == "string", f"expected properties.id.type 'string', got {fetched_id_type!r}"

    err = _client_error(
        lambda: apigw.create_model(
            restApiId=api_id,
            name=model_name,
            contentType="application/json",
            schema=json.dumps(schema),
        )
    )
    assert err.get("Code") == "ConflictException", f"expected ConflictException for duplicate name, got {err.get('Code')!r}"
    assert err.get("Message") == "Model name already exists for this REST API", (
        f"expected the exact duplicate-name message, got {err.get('Message')!r}"
    )

    models = apigw.get_models(restApiId=api_id)["items"]
    dup_count = sum(1 for m in models if m["name"] == model_name)
    assert dup_count == 1, f"expected exactly 1 model named {model_name!r} after rejected duplicate, found {dup_count}"

    # Restore: remove the model whose presence forbade the duplicate create, and prove the
    # identical call now succeeds, which a bare rejection assertion would miss.
    apigw.delete_model(restApiId=api_id, modelName=model_name)
    gone = _client_error(lambda: apigw.get_model(restApiId=api_id, modelName=model_name))
    assert gone.get("Code") == "NotFoundException", f"expected NotFoundException after delete, got {gone.get('Code')!r}"
    assert gone.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message, got {gone.get('Message')!r}"
    )

    apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=json.dumps(schema),
    )
    restored = apigw.get_model(restApiId=api_id, modelName=model_name)
    restored_title = json.loads(restored["schema"])["title"]
    assert restored_title == model_name, (
        f"expected recreated model's schema title {model_name!r}, got {restored_title!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
