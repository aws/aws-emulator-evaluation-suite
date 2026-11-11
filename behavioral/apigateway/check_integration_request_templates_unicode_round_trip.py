"""integration-request-templates-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "integration-request-templates-unicode-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VTL request templates with unicode/multi-line content persist unchanged through PutIntegration."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "integration-request-templates-unicode-round-trip"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="POST", authorizationType="NONE")

    vtl_template = (
        "#set($allParams = $input.params())\n"
        "{\n"
        '  "message": "こんにちは世界 – emoji: 🚀",\n'
        '  "café": "naïve-Ω",\n'
        '  "note": "line1\\nline2\\ttabbed"\n'
        "}\n"
    )
    request_templates = {"application/json": vtl_template}

    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="POST",
        type="MOCK",
        requestTemplates=request_templates,
    )

    got = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    assert got["requestTemplates"]["application/json"] == vtl_template, got["requestTemplates"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
