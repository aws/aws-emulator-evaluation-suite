"""op-contract-getApiKey."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-getApiKey"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApiKey with includeValue=True returns the exact created key value; a
    lookup of a nonexistent key id 404s."""
    apigw = ctx.client("apigateway")

    key_name = ctx.unique_name("sim2real-behav-key-")
    created = apigw.create_api_key(
        name=key_name, enabled=True, description="behavioral check key", tags={"sim2real": CHECK}
    )
    key_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    got = apigw.get_api_key(apiKey=key_id, includeValue=True)
    assert got["id"] == key_id, f"expected id {key_id!r}, got {got['id']!r}"
    assert got["name"] == key_name, f"expected name {key_name!r}, got {got['name']!r}"
    assert got["enabled"] is True, f"expected enabled=True, got {got['enabled']!r}"
    assert got["value"] == created["value"], (
        f"expected value {created['value']!r}, got {got['value']!r}"
    )
    assert len(got["value"]) >= 20, (  # API Gateway API keys are long random strings
        f"expected a long random key value, got {len(got['value'])} chars: {got['value']!r}"
    )

    # includeValue=False (the default) must NOT return the secret value
    got_no_value = apigw.get_api_key(apiKey=key_id)
    assert "value" not in got_no_value, (
        f"includeValue defaults to False but the value leaked: {got_no_value.get('value')!r}"
    )

    code, message = _error(lambda: apigw.get_api_key(apiKey="nonexistent" + ctx.unique_name("")))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Invalid API Key identifier specified", (
        f"unexpected NotFoundException message {message!r}"
    )


def _error(fn) -> Any:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
