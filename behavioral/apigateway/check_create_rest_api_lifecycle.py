"""create-rest-api-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rest-api-lifecycle"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return the botocore error (code, message, HTTP status). An unexpected success
    raises, so accepted input is reported as accepted rather than as a wrong error code."""
    try:
        result = fn()
    except ClientError as err:
        status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.response["Error"]["Code"], err.response["Error"].get("Message"), status
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _throttle_retry(fn, *, attempts=10, base_delay=15.0, max_delay=35.0):
    """Call fn(), retrying through API Gateway's low account-level control-plane
    throttle. REST-API mutations (notably DeleteRestApi, capped at ~1 req/30s)
    share a bucket that refills slowly, so the SDK's own short retries can exhaust
    and surface TooManyRequestsException on legitimate calls. Retry with
    bucket-sized backoff over a generous (~5 min) budget; any other error
    propagates immediately, and a success returns fn()'s result. Re-raises the
    last throttle if it never clears within budget."""
    delay = base_delay
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            last = exc
            if i < attempts - 1:
                time.sleep(min(delay, max_delay))
                delay *= 2
    raise last


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRestApi reflects CreateRestApi's fields, and after DeleteRestApi the id is refused by reads and
    mutations."""
    ag = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-apigw-lifecycle-")
    created = _throttle_retry(lambda: ag.create_rest_api(
        name=name, description="fidelity check",
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))
    rest_api_id = created["id"]
    def _cleanup_delete():
        # NotFound-tolerant: on the happy path the check itself deletes the api, and
        # _throttle_retry re-raises everything except TooManyRequestsException -- so a strict
        # teardown delete would fail on the check's own success.
        try:
            _throttle_retry(lambda: ag.delete_rest_api(restApiId=rest_api_id))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_delete)

    got = ag.get_rest_api(restApiId=rest_api_id)
    assert got["name"] == name, f"expected name {name}, got {got['name']}"
    assert got["id"] == rest_api_id, f"expected id {rest_api_id}, got {got['id']}"
    assert got.get("description") == "fidelity check", (
        f"expected description 'fidelity check', got {got.get('description')!r}"
    )
    types = got.get("endpointConfiguration", {}).get("types")
    assert types == ["REGIONAL"], f"expected endpointConfiguration.types ['REGIONAL'], got {types!r}"
    assert got.get("tags") == {"sim2real": CHECK}, f"expected tags {{'sim2real': {CHECK!r}}}, got {got.get('tags')!r}"

    try:
        _throttle_retry(lambda: ag.delete_rest_api(restApiId=rest_api_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TooManyRequestsException":
            # DeleteRestApi's ~1-req/30s bucket never refilled within budget, so the
            # delete->gone assertion below was never exercised. Skip rather than return:
            # returning would report a PASS for a run that verified nothing, making
            # "not exercised" indistinguishable from "verified". Cleanup still deletes it.
            raise AssertionError(
                "DeleteRestApi throttled (TooManyRequestsException) for the whole retry "
                "budget; the delete->NotFound assertion could not be exercised"
            ) from exc
        raise
    # Beat 1: the by-id read is NotFoundException, 404, with the exact message.
    code, message, status = _error(lambda: ag.get_rest_api(restApiId=rest_api_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx for GetRestApi after delete, got {status!r}"
    expected_message = f"Invalid API identifier specified {ctx.account}:{rest_api_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Beat 2: the deleted API is absent from the full (paginated) listing.
    listed = [
        item
        for page in ag.get_paginator("get_rest_apis").paginate()
        for item in page.get("items", [])
    ]
    survivors = [i for i in listed if i.get("id") == rest_api_id or i.get("name") == name]
    assert survivors == [], f"deleted REST API still listed by GetRestApis: {survivors!r}"

    # Beat 3: a mutation on the dead id is refused the same way.
    mutate_code, mutate_message, mutate_status = _error(lambda: ag.update_rest_api(
        restApiId=rest_api_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "post-delete"}],
    ))
    assert mutate_code == "NotFoundException", (
        f"expected a mutation on the deleted restApiId to fail with NotFoundException, "
        f"got {mutate_code}"
    )
    assert isinstance(mutate_status, int) and 400 <= mutate_status < 500, f"expected HTTP 4xx for UpdateRestApi after delete, got {mutate_status!r}"
    expected_message = f"Invalid API identifier specified {ctx.account}:{rest_api_id}"
    assert mutate_message == expected_message, f"expected the message {expected_message!r}, got {mutate_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
