"""get-deployments-ordered-by-creation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployments-ordered-by-creation"
GROUP = "ordering"
SERVICES = ["apigateway"]

_COUNT = 4


def _retrying(fn, *, max_attempts: int = 8, base_delay: float = 2.0):
    """Call fn(), retrying with exponential backoff on TooManyRequestsException."""
    attempt = 0
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            attempt += 1
            if code != "TooManyRequestsException" or attempt >= max_attempts:
                raise
            time.sleep(base_delay * attempt)


def _poll_until_all_visible(list_fn, expected_count: int, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Poll list_fn() until it returns expected_count items: GetDeployments is not
    read-after-write consistent and can briefly miss the newest deployments."""
    deadline = time.monotonic() + timeout_s
    items = list_fn()
    while len(items) < expected_count and time.monotonic() < deadline:
        time.sleep(interval_s)
        items = list_fn()
    return items


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every created deployment appears exactly once in GetDeployments, and paging with a small
    limit reconstructs exactly the unpaginated order (no reorder, duplicate or drop).
    GetDeployments guarantees no creation-time ordering, so only this consistency is asserted."""
    apigw = ctx.client("apigateway")

    api_id = _retrying(
        lambda: apigw.create_rest_api(
            name=ctx.unique_name("sim2real-depsorder-"),
            endpointConfiguration={"types": ["REGIONAL"]},
            tags={"sim2real": "deployments-ordered-by-creation"},
        )
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    expected_descriptions = set()
    for i in range(_COUNT):
        desc = f"sim2real-dep-{i}"
        _retrying(lambda desc=desc: apigw.create_deployment(restApiId=api_id, description=desc))
        expected_descriptions.add(desc)
        # Give each deployment a clearly distinct creation timestamp: API
        # Gateway's createdDate has whole-second granularity, and creating
        # deployments back-to-back within the same second risks a tied sort
        # key whose secondary ordering is not guaranteed to match call order.
        time.sleep(2.5)

    full_items = _poll_until_all_visible(
        lambda: _retrying(lambda: apigw.get_deployments(restApiId=api_id))["items"],
        expected_count=_COUNT,
    )
    full_descriptions = [item["description"] for item in full_items]
    assert len(full_descriptions) == _COUNT and set(full_descriptions) == expected_descriptions, (
        f"expected every deployment in {sorted(expected_descriptions)} to be listed exactly once, "
        f"got {full_descriptions}"
    )

    collected = []
    kwargs = {"restApiId": api_id, "limit": 2}
    max_pages = _COUNT + 1  # limit=2 over _COUNT items needs at most _COUNT/2 pages; +1 guards a token that never terminates
    for _ in range(max_pages):
        resp = _retrying(lambda kwargs=kwargs: apigw.get_deployments(**kwargs))
        collected.extend(item["description"] for item in resp["items"])
        token = resp.get("position")
        if not token:
            break
        kwargs["position"] = token
    else:
        raise AssertionError(f"GetDeployments pagination did not terminate within {max_pages} pages")
    assert collected == full_descriptions, (
        f"paginated order {collected} != unpaginated order {full_descriptions} "
        "(GetDeployments pagination must reconstruct the same order as a full fetch, "
        "even though that order is not guaranteed to match creation order)"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

