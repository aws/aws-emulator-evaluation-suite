"""model-schema-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "model-schema-numeric-precision-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A model JSON schema with high-precision numeric literals is preserved byte-for-byte."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "model-schema-numeric-precision-round-trip"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # High-precision numeric literals that would be corrupted by a float round-trip
    # (e.g. json.loads -> json.dumps with default float parsing).
    schema = (
        '{"$schema":"http://json-schema.org/draft-04/schema#",'
        '"title":"Precise",'
        '"type":"object",'
        '"properties":{'
        '"pi":{"type":"number","default":3.14159265358979323846},'
        '"big":{"type":"number","minimum":123456789012345.6789},'
        '"tiny":{"type":"number","maximum":0.100000000000000005551115}'
        '}}'
    )

    model_name = ctx.unique_name("SimModel").replace("-", "")
    apigw.create_model(
        restApiId=api_id, name=model_name, contentType="application/json", schema=schema
    )
    ctx.on_cleanup(lambda: apigw.delete_model(restApiId=api_id, modelName=model_name))

    got = apigw.get_model(restApiId=api_id, modelName=model_name)
    assert got["schema"] == schema, (
        f"schema not preserved byte-for-byte: sent={schema!r} got={got['schema']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
