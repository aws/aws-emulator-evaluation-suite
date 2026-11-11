"""update-rest-api-patch-description."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-rest-api-patch-description"
GROUP = 'rest-api'
SERVICES = ['apigateway']


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRestApi with a 'replace' patch operation persists the new value."""
    ag = ctx.client("apigateway")
    rest_api_id = _create_api(ctx, ag)
    updated = ctx.unique_name("sim2real-behav-desc-")

    result = ag.update_rest_api(
        restApiId=rest_api_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": updated}],
    )
    assert result["description"] == updated, (
        f"expected {updated}, got {result.get('description')}"
    )

    got = ag.get_rest_api(restApiId=rest_api_id)
    assert got["description"] == updated, (
        f"description did not persist: {got.get('description')}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
