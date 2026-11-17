"""apigw-put-method-rejects-multivaluequerystring-as-request-parameter-location."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-put-method-rejects-multivaluequerystring-as-request-parameter-location"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]

_THROTTLED = ("TooManyRequestsException", "Too Many Requests")


def _error_pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _retry_throttled(fn, *, attempts=10):
    """Call fn(), retrying only the control plane's own per-account throttle."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _error_pair(exc) != _THROTTLED or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2**attempt)) + random.uniform(0, 0.2))


def _delete_rest_api_quota_aware(ag, api_id: str, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd per account; retry the throttle across a bounded window."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            if _error_pair(exc) != _THROTTLED or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMethod rejects a requestParameters key in the multivaluequerystring location with
    BadRequestException and creates no method, while the same name under querystring is accepted.
    """
    ag = ctx.client("apigateway")
    api_id = _retry_throttled(
        lambda: ag.create_rest_api(
            name=ctx.unique_name("sim2real-behav-apigw-"), tags={"sim2real": CHECK}
        )
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(ag, api_id))

    root_id = ag.get_resources(restApiId=api_id)["items"][0]["id"]
    resource_id = _retry_throttled(
        lambda: ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")
    )["id"]

    bad_key = "method.request.multivaluequerystring.tag"
    code, message = _error(
        lambda: ag.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            authorizationType="NONE",
            requestParameters={bad_key: True},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "Invalid mapping expression specified: Validation Result: warnings : [], "
        f"errors : [Invalid mapping expression specified: {bad_key}]"
    ), f"unexpected message: {message!r}"

    # effect absent: no method was created on this resource.
    get_code, get_message = _error(
        lambda: ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert get_code == "NotFoundException", (
        f"a method exists despite the rejected PutMethod, got {get_code!r}"
    )
    assert get_message == "Invalid Method identifier specified", (
        f"unexpected message: {get_message!r}"
    )

    # positive control: the same parameter name under the querystring location succeeds.
    ag.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={"method.request.querystring.tag": True},
    )
    fetched = ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    assert fetched["requestParameters"] == {"method.request.querystring.tag": True}, (
        f"control: expected method.request.querystring.tag, got {fetched.get('requestParameters')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
