"""update-method-http-method-immutable-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-method-http-method-immutable-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethod rejects an attempt to mutate the immutable httpMethod path; unrelated valid patches still succeed."""
    apigw = ctx.client("apigateway")
    api_id, root_id = _create_rest_api(ctx)

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    # Positive control: a supported patch path succeeds.
    control = apigw.update_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/apiKeyRequired", "value": "true"}],
    )
    assert control["apiKeyRequired"] is True, (
        f"positive control: expected apiKeyRequired=True, got {control['apiKeyRequired']!r}"
    )

    # Negative: httpMethod is not a patchable path on UpdateMethod.
    err = _client_error(
        lambda: apigw.update_method(
            restApiId=api_id, resourceId=root_id, httpMethod="GET",
            patchOperations=[{"op": "replace", "path": "/httpMethod", "value": "POST"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid patch path /httpMethod", (
        f"expected the exact patch-path refusal message, got {err.get('Message')!r}"
    )

    fetched = apigw.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert fetched["httpMethod"] == "GET", "rejected patch must not have mutated the http verb"
    assert fetched["apiKeyRequired"] is True, "the prior valid mutation must remain intact after the rejected patch"


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-bh-api-"), tags={"sim2real": CHECK})
    api_id = resp["id"]
    root_id = resp["rootResourceId"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    return api_id, root_id


def _client_error(fn) -> dict:
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a patch real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this httpMethod patch, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
