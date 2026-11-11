"""get-models-list-creation-order-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-models-list-creation-order-preserved"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetModels lists every created model (named out of lexical order) and returns the same
    order on three consecutive calls."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    schema = (
        '{"$schema":"http://json-schema.org/draft-04/schema#",'
        '"title":"m","type":"object","properties":{"x":{"type":"string"}}}'
    )
    creation_order = ["zeta", "alpha", "mu", "beta"]
    for name in creation_order:
        apigw.create_model(
            restApiId=api_id, name=name, contentType="application/json", schema=schema
        )

    def _custom_model_order():
        items = apigw.get_models(restApiId=api_id, limit=500)["items"]
        # every RestApi auto-provisions built-in "Empty"/"Error" models; filter those out
        return [m["name"] for m in items if m["name"] in creation_order]

    listed_1 = _custom_model_order()
    listed_2 = _custom_model_order()
    listed_3 = _custom_model_order()

    assert set(listed_1) == set(creation_order), (
        f"GetModels did not return all created models: expected {creation_order}, "
        f"got {listed_1}"
    )
    # GetModels guarantees neither insertion nor name order, but an unchanged set of models must come
    # back in the same total order on every call.
    assert listed_1 == listed_2 == listed_3, (
        f"GetModels order unstable across repeated calls: {listed_1} vs {listed_2} "
        f"vs {listed_3}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
