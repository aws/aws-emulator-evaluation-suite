"""concurrent-tag-resource-merge."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-merge"
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


def _delete_rest_api(apigw, api_id: str, timeout_s: float = 120.0) -> None:
    """Teardown: DeleteRestApi, retried while API Gateway throttles it (its per-account delete rate
    is low); a RestApi already gone is fine."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls with disjoint keys on the same ARN both apply."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    tag_sets = [
        {"sim2realRaceKeyA": "valueA"},
        {"sim2realRaceKeyB": "valueB"},
    ]

    def _tag(tag_set: dict[str, str]) -> None:
        _retry_contended(lambda: apigw.tag_resource(resourceArn=resource_arn, tags=tag_set))

    with ThreadPoolExecutor(max_workers=len(tag_sets)) as pool:
        list(pool.map(_tag, tag_sets))

    applied_tags = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert applied_tags.get("sim2realRaceKeyA") == "valueA", f"tags missing/merged incorrectly: {applied_tags}"
    assert applied_tags.get("sim2realRaceKeyB") == "valueB", f"tags missing/merged incorrectly: {applied_tags}"

    # untagging one key concurrently with re-tagging the other must not disturb the untouched key
    def _untag_a() -> None:
        _retry_contended(lambda: apigw.untag_resource(resourceArn=resource_arn, tagKeys=["sim2realRaceKeyA"]))

    def _retag_b() -> None:
        _retry_contended(lambda: apigw.tag_resource(resourceArn=resource_arn, tags={"sim2realRaceKeyB": "valueB2"}))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda fn: fn(), [_untag_a, _retag_b]))

    final_tags = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert "sim2realRaceKeyA" not in final_tags, f"key A should have been removed: {final_tags}"
    assert final_tags.get("sim2realRaceKeyB") == "valueB2", f"key B update lost: {final_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
