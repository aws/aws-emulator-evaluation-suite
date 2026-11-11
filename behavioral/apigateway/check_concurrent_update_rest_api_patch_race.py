"""concurrent-update-rest-api-patch-race."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-rest-api-patch-race"
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
    """Concurrent UpdateRestApi patches on disjoint fields both apply, unrelated fields untouched."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"),
        description="original-description",
        minimumCompressionSize=0,
        tags={"sim2real": "update-rest-api-patch-race"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    original_name = api["name"]

    def _patch_description() -> None:
        _retry_contended(lambda: apigw.update_rest_api(
            restApiId=api_id,
            patchOperations=[
                {"op": "replace", "path": "/description", "value": "race-description"}
            ],
        ))

    def _patch_compression() -> None:
        _retry_contended(lambda: apigw.update_rest_api(
            restApiId=api_id,
            patchOperations=[
                {"op": "replace", "path": "/minimumCompressionSize", "value": "512"}
            ],
        ))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda fn: fn(), [_patch_description, _patch_compression]))

    final = apigw.get_rest_api(restApiId=api_id)
    assert final["description"] == "race-description", f"description patch lost: {final}"
    assert final["minimumCompressionSize"] == 512, f"minimumCompressionSize patch lost: {final}"
    # unrelated field (name), touched by neither racer, must survive untouched
    assert final["name"] == original_name, f"unrelated field 'name' was clobbered: {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
