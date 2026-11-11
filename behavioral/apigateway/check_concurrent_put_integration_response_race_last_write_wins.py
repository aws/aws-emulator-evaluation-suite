"""concurrent-put-integration-response-race-last-write-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-integration-response-race-last-write-wins"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutIntegrationResponse calls on the same statusCode converge to exactly one
    caller's full payload (last-write-wins) with no cross-call field merge."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-race-ir-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    num_racers = 8
    max_attempts = 6

    def _race(i: int):
        # Real AWS optimistically locks the integration-response resource: a racer that loses
        # the write gets ConflictException("concurrent modification"), not a silent merge or a
        # queued apply. Retrying is the correct response to that contention, not a workaround —
        # it is how a real caller would resolve the same race.
        last_exc = None
        for attempt in range(max_attempts):
            try:
                return apigw.put_integration_response(
                    restApiId=api_id,
                    resourceId=root_id,
                    httpMethod="GET",
                    statusCode="200",
                    responseTemplates={
                        "application/json": json.dumps({"marker": i}),
                        "text/plain": f"marker-{i}",
                    },
                )
            except apigw.exceptions.ConflictException as exc:
                last_exc = exc
                time.sleep(0.2 * (attempt + 1))
        raise AssertionError(
            f"racer {i} never completed PutIntegrationResponse after {max_attempts} attempts "
            f"racing against concurrent writers; last error: {last_exc}"
        )

    with ThreadPoolExecutor(max_workers=num_racers) as pool:
        results = list(pool.map(_race, range(num_racers)))
    assert len(results) == num_racers, f"expected {num_racers} successful racer responses, got {len(results)}"

    final = apigw.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    templates = final["responseTemplates"]
    json_marker = json.loads(templates["application/json"])["marker"]
    text_marker = int(templates["text/plain"].rsplit("-", 1)[1])

    assert 0 <= json_marker < num_racers, f"unexpected marker value {json_marker}"
    assert json_marker == text_marker, (
        f"partial merge detected: application/json marker={json_marker} but "
        f"text/plain marker={text_marker}; a single racer's full call should have won atomically"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
