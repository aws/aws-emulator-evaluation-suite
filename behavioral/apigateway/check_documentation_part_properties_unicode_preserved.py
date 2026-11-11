"""documentation-part-properties-unicode-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "documentation-part-properties-unicode-preserved"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationPart with unicode text embedded in its properties JSON blob;
    GetDocumentationPart must return the properties unchanged, unicode intact."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    properties_obj = {
        "description": "文档说明 😀 — Beschreibung für Endpunkt",
        "note": "Ünïcödé: café, naïve, Москва, 北京市, 🇯🇵🎉",
    }
    properties_str = json.dumps(properties_obj, ensure_ascii=False)

    created = apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties=properties_str,
    )
    part_id = created["id"]
    ctx.on_cleanup(
        lambda: apigw.delete_documentation_part(restApiId=api_id, documentationPartId=part_id)
    )

    fetched = apigw.get_documentation_part(restApiId=api_id, documentationPartId=part_id)
    assert fetched["properties"] == properties_str, (
        f"properties bytes mutated across round trip: sent={properties_str!r} got={fetched['properties']!r}"
    )
    round_tripped = json.loads(fetched["properties"])
    assert round_tripped == properties_obj, (
        f"properties mutated across round trip: sent={properties_obj!r} got={round_tripped!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
