"""api-key-customer-supplied-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "api-key-customer-supplied-value-round-trip"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A customer-supplied API key value, including special characters, round-trips unchanged."""
    apigw = ctx.client("apigateway")

    custom_value = "MyCustom_Key-2024!@#Value.Test0000"  # >=20 chars, includes special characters
    created = apigw.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"),
        value=custom_value,
        enabled=True,
        tags={"sim2real": CHECK},
    )
    key_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    assert created["value"] == custom_value, created["value"]

    got = apigw.get_api_key(apiKey=key_id, includeValue=True)
    assert got["value"] == custom_value, got["value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
