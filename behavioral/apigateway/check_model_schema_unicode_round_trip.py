"""model-schema-unicode-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-schema-unicode-round-trip"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel with unicode title/description in its JSON schema; GetModel must
    return the schema unmangled (no lossy escaping / re-encoding of the unicode text)."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    schema_obj = {
        "title": "商品情報 😀 Produkt-Übersicht",
        "description": "Ünïcödé tëst: café, naïve, 北京, Москва, 😀🎉, emoji-flag 🇯🇵",
        "type": "object",
        "properties": {"名前": {"type": "string", "description": "識別子"}},
    }
    schema_str = json.dumps(schema_obj, ensure_ascii=False)

    # Model names must be alphanumeric only (no hyphens allowed).
    model_name = ctx.unique_name("Sim2RealModel").replace("-", "")

    created = apigw.create_model(
        restApiId=api_id,
        name=model_name,
        contentType="application/json",
        schema=schema_str,
    )
    assert created["name"] == model_name, (
        f"CreateModel response name mismatch: expected {model_name!r}, got {created.get('name')!r}"
    )

    fetched = apigw.get_model(restApiId=api_id, modelName=model_name)
    round_tripped = json.loads(fetched["schema"])
    assert round_tripped == schema_obj, (
        f"schema mutated across round trip: sent={schema_obj!r} got={round_tripped!r}"
    )

    # the delete is already happening (directly or via the rest api's cascade) — make it a
    # free negative: an independent read must 404, and a mutation on the dead id must too.
    apigw.delete_model(restApiId=api_id, modelName=model_name)
    err = _client_error(lambda: apigw.get_model(restApiId=api_id, modelName=model_name))
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException reading a deleted model, got {err.get('Code')!r}"
    assert err.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message from GetModel, got {err.get('Message')!r}"
    )
    err2 = _client_error(
        lambda: apigw.update_model(
            restApiId=api_id,
            modelName=model_name,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert err2.get("Code") == "NotFoundException", f"expected NotFoundException patching a deleted model, got {err2.get('Code')!r}"
    assert err2.get("Message") == f"Invalid model name specified: {model_name}", (
        f"expected the exact NotFound message from UpdateModel, got {err2.get('Message')!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name, tags={"sim2real": "model-schema-unicode-round-trip"})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
