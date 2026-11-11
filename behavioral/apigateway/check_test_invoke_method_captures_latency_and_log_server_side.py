"""test-invoke-method-captures-latency-and-log-server-side."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "test-invoke-method-captures-latency-and-log-server-side"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeMethod's response carries server-captured latency and an execution log that
    reflects the actual, per-request integration/template execution rather than a static stub."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-latlog-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    marker = ctx.unique_name("sim2real-logmarker")

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": f'{{"marker": "{marker}"}}'},
    )

    wall_start = time.monotonic()
    resp = apigw.test_invoke_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    wall_ms = (time.monotonic() - wall_start) * 1000

    assert "latency" in resp, "TestInvokeMethod response missing 'latency'"
    latency = resp["latency"]
    assert isinstance(latency, (int, float)), f"latency has unexpected type: {type(latency)}"
    assert 0 <= latency < 60_000, f"latency out of plausible range: {latency}"
    # The reported latency is the server's own per-request execution time, so it cannot exceed
    # the client-observed wall-clock round trip (which also includes network/API overhead) by
    # more than generous slack -- a canned/hardcoded latency unrelated to this call would not be
    # bound by what the client actually measured.
    assert latency <= wall_ms + 5_000, (
        f"reported latency {latency}ms is implausible next to the {wall_ms:.0f}ms the client "
        "actually observed for this call -- looks like a canned value, not a real measurement"
    )

    assert marker in resp["body"], f"response body does not reflect our integration template: {resp['body']!r}"

    log = resp.get("log", "")
    assert marker in log, (
        "execution log does not mention our per-request response-template marker; a static "
        f"stub log would not vary with the actual configured integration. log={log!r}"
    )
    assert log.count("\n") >= 3, f"execution log looks too short/generic to be a real trace: {log!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
