"""delete-integration-then-get-not-found."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-integration-then-get-not-found"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteIntegration removes the integration so GetIntegration 404s afterwards, and the
    method identifier is reusable: a fresh PutIntegration on the same method succeeds and is
    gettable with its own configuration rather than a tombstone."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-delint-"),
        tags={"sim2real": "delete-integration-then-get-not-found"},
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

    got = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert got["type"] == "MOCK", f"expected the positive control to report type MOCK, got {got.get('type')!r}"

    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")

    code, message = _error(lambda: apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET"))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == "Invalid Integration identifier specified", f"unexpected not-found message: {message!r}"

    # the identifier is reusable, not left in a tombstoned state: a fresh PutIntegration on the
    # same method must succeed and be gettable with the new configuration, not the deleted one.
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 201}'},
    )
    recreated = apigw.get_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert recreated["type"] == "MOCK", f"expected the recreated integration to report type MOCK, got {recreated.get('type')!r}"
    assert recreated["requestTemplates"]["application/json"] == '{"statusCode": 201}', (
        f"expected the recreated integration's own template, got {recreated.get('requestTemplates')!r}"
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
