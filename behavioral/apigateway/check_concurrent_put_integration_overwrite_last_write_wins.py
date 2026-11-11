"""concurrent-put-integration-overwrite-last-write-wins."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-integration-overwrite-last-write-wins"
GROUP = "concurrency"
SERVICES = ["apigateway"]

_CONFIG_A = {
    "type": "MOCK",
    "requestTemplates": {"application/json": '{"statusCode": 200}'},
    "passthroughBehavior": "WHEN_NO_MATCH",
}
_CONFIG_B = {
    "type": "MOCK",
    "requestTemplates": {"application/json": '{"statusCode": 201}'},
    "passthroughBehavior": "NEVER",
}


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
    """Two concurrent PutIntegration calls on the same method resolve to a single coherent
    last-write-wins state -- never a partial mix of the two configurations."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    def _put(config: dict) -> None:
        _retry_contended(
            lambda: apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", **config)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_put, _CONFIG_A)
        fut_b = pool.submit(_put, _CONFIG_B)
        fut_a.result()
        fut_b.result()

    final = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    got_pt = final["passthroughBehavior"]
    got_rt = final["requestTemplates"]["application/json"]

    matches_a = got_pt == _CONFIG_A["passthroughBehavior"] and got_rt == _CONFIG_A["requestTemplates"]["application/json"]
    matches_b = got_pt == _CONFIG_B["passthroughBehavior"] and got_rt == _CONFIG_B["requestTemplates"]["application/json"]

    assert matches_a or matches_b, (
        f"final integration state is a mix of both writers: passthroughBehavior={got_pt!r}, "
        f"requestTemplate={got_rt!r}"
    )
    assert matches_a != matches_b, "final state ambiguously matched both configs at once"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
