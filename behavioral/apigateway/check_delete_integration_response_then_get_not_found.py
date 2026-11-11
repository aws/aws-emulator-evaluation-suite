"""delete-integration-response-then-get-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-integration-response-then-get-not-found"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIntegrationResponse removes the mapping so GetIntegrationResponse 404s afterwards.

    Also proves the mapping stays dead under a second delete, and that the status
    code is reusable once re-mapped.
    """
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-delintresp-"))["id"]
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
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": "sim2real-marker-v1"},
    )

    got = apigw.get_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert got["responseTemplates"]["application/json"] == "sim2real-marker-v1", (
        f"expected the mapped template to persist, got {got.get('responseTemplates')!r}"
    )

    apigw.delete_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    code, message = _error(
        lambda: apigw.get_integration_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == "Invalid Response status code specified", f"unexpected not-found message: {message!r}"

    # mutation on the dead id also fails: a second delete of the same status code
    # must not silently succeed against a mapping that is already gone.
    code2, message2 = _error(
        lambda: apigw.delete_integration_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
    )
    assert code2 == "NotFoundException", (
        f"expected a second delete of the already-dead mapping to 404 too, got {code2!r}"
    )
    assert message2 == "Invalid Response status code specified", f"unexpected second-delete message: {message2!r}"

    # the status code is reusable once re-mapped -- delete does not poison the slot.
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": "sim2real-marker-v2"},
    )
    reput = apigw.get_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    assert reput["responseTemplates"]["application/json"] == "sim2real-marker-v2", (
        f"expected statusCode 200 to be reusable after delete, got {reput.get('responseTemplates')!r}"
    )


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
