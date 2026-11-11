"""integration-mapping-template-base64-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "integration-mapping-template-base64-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A mapping template body (VTL text embedding base64-encoded payload) set via PutIntegration
    is returned unchanged on GetIntegration."""
    apigw = ctx.client("apigateway")
    api_id, resource_id = _create_api_with_method(ctx)

    template_body = (
        "#set($body = $util.base64Encode($input.json('$')))\n"
        "{\n"
        '  "encoded": "SGVsbG8sIFdvcmxkISBBUElHYXRld2F5Cg==",\n'
        '  "raw": "$body",\n'
        '  "plusSlashEquals": "a+b/c=="\n'
        "}\n"
    )

    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="MOCK",
        requestTemplates={"application/json": template_body},
    )

    got = apigw.get_integration(restApiId=api_id, resourceId=resource_id, httpMethod="POST")
    returned_template = got["requestTemplates"]["application/json"]
    assert returned_template == template_body, (
        "mapping template body was not returned unchanged:\n"
        f"sent={template_body!r}\ngot={returned_template!r}"
    )


def _create_api_with_method(ctx) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resources = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="POST", authorizationType="NONE")
    return api_id, root_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
