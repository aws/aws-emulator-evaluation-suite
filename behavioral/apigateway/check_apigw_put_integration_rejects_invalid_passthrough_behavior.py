"""apigw-put-integration-rejects-invalid-passthrough-behavior."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-put-integration-rejects-invalid-passthrough-behavior"
GROUP = "parameter-mapping"
SERVICES = ["apigateway"]

_THROTTLED = ("TooManyRequestsException", "Too Many Requests")


def _error_pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _retry_throttled(fn, *, attempts: int = 10):
    """Call fn(), retrying only the control plane's own throttle with jittered backoff."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _error_pair(exc) != _THROTTLED or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutIntegration rejects a passthroughBehavior outside WHEN_NO_MATCH, NEVER and
    WHEN_NO_TEMPLATES, naming the valid options, and leaves the integration unset.
    """
    ag = ctx.client("apigateway")

    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"), tags={"sim2real": CHECK}
    ))["id"]
    ctx.on_cleanup(lambda: _retry_throttled(lambda: ag.delete_rest_api(restApiId=api_id)))

    root_id = ag.get_resources(restApiId=api_id)["items"][0]["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"))

    code, message = _error(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
        passthroughBehavior="sim2real-not-a-real-value",
    ))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    assert message == (
        "Invalid PassthroughBehavior specified. Valid options are "
        "WHEN_NO_MATCH,NEVER,WHEN_NO_TEMPLATES"
    ), f"unexpected message: {message!r}"

    # effect absent: the rejected call must not have created an integration.
    absent_code, absent_message = _error(
        lambda: ag.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET"))
    assert absent_code == "NotFoundException", (
        f"a rejected PutIntegration left an integration behind: {absent_code!r}"
    )
    assert absent_message == "Invalid Integration identifier specified", (
        f"unexpected message: {absent_message!r}"
    )

    # positive control: the same call with a valid passthroughBehavior succeeds.
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
        passthroughBehavior="WHEN_NO_MATCH",
    ))
    fetched = ag.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["passthroughBehavior"] == "WHEN_NO_MATCH", (
        f"control: expected WHEN_NO_MATCH, got {fetched.get('passthroughBehavior')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
