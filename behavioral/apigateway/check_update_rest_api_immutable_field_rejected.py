"""update-rest-api-immutable-field-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-rest-api-immutable-field-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRestApi rejects a patch of the immutable /id with BadRequestException; the id is kept.
    A /description patch on the same API still succeeds, so the rejection is specific to /id.
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)

    err = _client_error(
        lambda: ag.update_rest_api(
            restApiId=api_id,
            patchOperations=[{"op": "replace", "path": "/id", "value": "sim2realFAKEID"}],
        )
    )
    assert err.get("Code") == "BadRequestException", (
        f"expected BadRequestException patching the immutable /id field, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "Invalid patch path /id", (
        f"expected the exact patch-path refusal message, got {err.get('Message')!r}"
    )

    unchanged = ag.get_rest_api(restApiId=api_id)
    assert unchanged["id"] == api_id, (
        f"the rejected patch must not have changed the RestApi id, got {unchanged['id']!r}"
    )

    control = ag.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real control"}],
    )
    assert control.get("description") == "sim2real control", (
        f"expected the mutable /description patch to succeed on the same resource, "
        f"got {control.get('description')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
