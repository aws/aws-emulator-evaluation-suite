"""concurrent-tag-resource-merges-tags."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-merges-tags"
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
    """Parallel TagResource calls with distinct tag keys both persist without lost updates."""
    apigw = ctx.client("apigateway")
    region = ctx.region

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-tagrace-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resource_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"

    pairs = [("sim2realKeyA", "valueA"), ("sim2realKeyB", "valueB")]

    def _tagger(key: str, value: str) -> None:
        _retry_contended(lambda: apigw.tag_resource(resourceArn=resource_arn, tags={key: value}))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_tagger, k, v) for k, v in pairs]
        for f in futures:
            f.result()

    tags = apigw.get_tags(resourceArn=resource_arn)["tags"]
    for key, value in pairs:
        assert tags.get(key) == value, f"expected tag {key}={value!r}, got tags={tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
