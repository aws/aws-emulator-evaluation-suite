"""update-route-response-preserves-fields."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-route-response-preserves-fields"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-ws"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A partial UpdateRouteResponse (only ModelSelectionExpression) must not
    clear the ResponseModels set by the original CreateRouteResponse call."""
    apigw = ctx.client("apigatewayv2")

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-ws-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    model = apigw.create_model(
        ApiId=api_id,
        Name="Sim2RealModel",
        ContentType="application/json",
        Schema=json.dumps(
            {
                "$schema": "http://json-schema.org/draft-04/schema#",
                "title": "Sim2RealModel",
                "type": "object",
            }
        ),
    )
    model_name = model["Name"]

    route = apigw.create_route(ApiId=api_id, RouteKey="$default")
    route_id = route["RouteId"]

    created = apigw.create_route_response(
        ApiId=api_id,
        RouteId=route_id,
        RouteResponseKey="$default",
        ResponseModels={"200": model_name},
        ModelSelectionExpression="$request.body.action",
    )
    route_response_id = created["RouteResponseId"]
    assert created.get("ResponseModels") == {"200": model_name}, (
        f"CreateRouteResponse ResponseModels mismatch: {created.get('ResponseModels')}"
    )
    assert created.get("ModelSelectionExpression") == "$request.body.action", (
        "CreateRouteResponse ModelSelectionExpression mismatch: "
        f"{created.get('ModelSelectionExpression')}"
    )

    # Partial update: only change ModelSelectionExpression, do NOT resend ResponseModels.
    apigw.update_route_response(
        ApiId=api_id,
        RouteId=route_id,
        RouteResponseId=route_response_id,
        ModelSelectionExpression="$request.body.type",
    )

    got = apigw.get_route_response(
        ApiId=api_id, RouteId=route_id, RouteResponseId=route_response_id
    )
    assert got["ModelSelectionExpression"] == "$request.body.type", (
        f"ModelSelectionExpression not updated: {got.get('ModelSelectionExpression')}"
    )
    assert got.get("ResponseModels") == {"200": model_name}, (
        "ResponseModels was cleared by a partial UpdateRouteResponse that only "
        "touched ModelSelectionExpression"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
