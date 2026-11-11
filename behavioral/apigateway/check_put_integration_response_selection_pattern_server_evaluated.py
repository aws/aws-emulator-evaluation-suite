"""put-integration-response-selection-pattern-server-evaluated."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-integration-response-selection-pattern-server-evaluated"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The server evaluates integration response selectionPatterns against the actual MOCK
    backend result at TestInvokeMethod time, dynamically picking the matching response
    template rather than always returning a fixed/first-defined one."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-selpat-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={
            "application/json": "#set($code = $input.params('code'))\n{\"statusCode\": $code}"
        },
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="500")

    # Default (no selectionPattern) response used when the mocked backend result is 200.
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": '{"result": "ok-template"}'},
    )
    # Only used when the mocked backend result matches the 5xx pattern.
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="500",
        selectionPattern="5\\d{2}",
        responseTemplates={"application/json": '{"result": "error-template"}'},
    )

    ok_resp = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        pathWithQueryString="/?code=200",
        headers={"Content-Type": "application/json"},
    )
    err_resp = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        pathWithQueryString="/?code=500",
        headers={"Content-Type": "application/json"},
    )

    assert ok_resp["status"] == 200, f"expected 200, got {ok_resp['status']}"
    assert "ok-template" in ok_resp["body"], f"unexpected body for code=200: {ok_resp['body']!r}"
    assert "error-template" not in ok_resp["body"], (
        f"code=200 must select the default (no selectionPattern) response, not the 5xx "
        f"template, got body {ok_resp['body']!r}"
    )

    assert err_resp["status"] == 500, f"expected 500, got {err_resp['status']}"
    assert "error-template" in err_resp["body"], f"unexpected body for code=500: {err_resp['body']!r}"
    assert "ok-template" not in err_resp["body"], (
        f"code=500 must select the selectionPattern='5\\d{{2}}' response, not the default "
        f"template, got body {err_resp['body']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
