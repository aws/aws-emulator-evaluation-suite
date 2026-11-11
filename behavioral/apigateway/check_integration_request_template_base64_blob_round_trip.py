"""integration-request-template-base64-blob-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "integration-request-template-base64-blob-round-trip"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded binary blob embedded in a mapping-template string on an
    integration must be returned byte-for-byte identical by GetIntegration -- no
    re-encoding, whitespace normalization, or truncation of the template body."""
    apigw = ctx.client("apigateway")
    api_id = _create_rest_api(ctx)

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="POST", authorizationType="NONE"
    )
    ctx.on_cleanup(
        lambda: apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    )

    blob_b64 = base64.b64encode(os.urandom(96)).decode("ascii")
    template = (
        '#set($blob = "' + blob_b64 + '")\n'
        "#set($decoded = $util.base64Decode($blob))\n"
        '{"payload": "$util.escapeJavaScript($blob)"}'
    )

    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="POST",
        type="MOCK",
        requestTemplates={"application/json": template},
    )

    fetched = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="POST")
    returned_template = fetched["requestTemplates"]["application/json"]
    assert returned_template == template, (
        "base64-blob mapping template mutated across round trip:\n"
        f"sent={template!r}\ngot={returned_template!r}"
    )


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-apigw-")
    resp = apigw.create_rest_api(name=name, tags={"sim2real": "integration-request-template-base64-blob-round-trip"})
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
