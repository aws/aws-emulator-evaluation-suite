"""get-request-validators-lists-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-request-validators-lists-created"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRequestValidators enumerates every request validator created for a REST
    API via CreateRequestValidator, including their validateRequestBody /
    validateRequestParameters flags.
    """
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    name_body = ctx.unique_name("sim2real-validator-body-")
    name_params = ctx.unique_name("sim2real-validator-params-")

    v_body = apigw.create_request_validator(
        restApiId=api_id,
        name=name_body,
        validateRequestBody=True,
        validateRequestParameters=False,
    )
    v_params = apigw.create_request_validator(
        restApiId=api_id,
        name=name_params,
        validateRequestBody=False,
        validateRequestParameters=True,
    )

    listing = apigw.get_request_validators(restApiId=api_id)
    items = {item["id"]: item for item in listing["items"]}

    assert len(items) == 2, f"expected exactly 2 validators, got {len(items)}: {items}"

    assert v_body["id"] in items, f"{v_body['id']} (body validator) missing from listing: {items}"
    got_body = items[v_body["id"]]
    assert got_body["name"] == name_body, f"expected name {name_body!r}, got {got_body['name']!r}"
    assert got_body["validateRequestBody"] is True, f"expected validateRequestBody True, got {got_body['validateRequestBody']!r}"
    assert got_body["validateRequestParameters"] is False, f"expected validateRequestParameters False, got {got_body['validateRequestParameters']!r}"

    assert v_params["id"] in items, f"{v_params['id']} (params validator) missing from listing: {items}"
    got_params = items[v_params["id"]]
    assert got_params["name"] == name_params, f"expected name {name_params!r}, got {got_params['name']!r}"
    assert got_params["validateRequestBody"] is False, f"expected validateRequestBody False, got {got_params['validateRequestBody']!r}"
    assert got_params["validateRequestParameters"] is True, f"expected validateRequestParameters True, got {got_params['validateRequestParameters']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
