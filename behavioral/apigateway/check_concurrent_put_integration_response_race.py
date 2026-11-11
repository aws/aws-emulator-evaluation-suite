"""concurrent-put-integration-response-race."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-integration-response-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


def _retry_contended(fn, attempts: int = 8):
    """Call fn(), retrying while API Gateway refuses it for a concurrent modification of the same
    resource (ConflictException) or throttles it; a caller resolves that contention by retrying."""
    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ConflictException", "TooManyRequestsException") or attempt == attempts - 1:
                raise
            time.sleep(0.2 * (attempt + 1))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutIntegrationResponse writes for the same status code converge to a
    single, internally-consistent final response (either wholly A's payload or wholly B's),
    never a merge of A's template with B's response parameters."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-restapi-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_items = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(i["id"] for i in root_items if i["path"] == "/")

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseParameters={"method.response.header.X-Source": False},
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    templates_a = {"application/json": "TEMPLATE-A"}
    params_a = {"method.response.header.X-Source": "'A'"}
    templates_b = {"application/json": "TEMPLATE-B"}
    params_b = {"method.response.header.X-Source": "'B'"}

    def _put(templates, params):
        return _retry_contended(lambda: apigw.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            selectionPattern="",
            responseTemplates=templates,
            responseParameters=params,
        ))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_put, templates_a, params_a)
        fut_b = pool.submit(_put, templates_b, params_b)
        fut_a.result()
        fut_b.result()

    final = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    final_templates = final.get("responseTemplates", {})
    final_params = final.get("responseParameters", {})

    is_a = final_templates == templates_a and final_params == params_a
    is_b = final_templates == templates_b and final_params == params_b
    assert is_a or is_b, (
        f"integration response is neither wholly A nor wholly B (partial merge?): "
        f"templates={final_templates} params={final_params}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
