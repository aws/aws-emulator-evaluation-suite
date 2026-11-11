"""create-api-key-duplicate-value-conflict."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "create-api-key-duplicate-value-conflict"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey with a value that collides with an existing key fails with ConflictException and
    creates no second key, a distinct value succeeds, and once the colliding key is deleted the same
    value is accepted again."""
    apigw = ctx.client("apigateway")

    suffix = ctx.unique_name("x").replace("-", "")[-14:]
    shared_value = f"sim2realDupKeyTestValue{suffix}"
    assert 20 <= len(shared_value) <= 128

    key1 = apigw.create_api_key(
        name=ctx.unique_name("sim2real-apikey1-"),
        enabled=True,
        value=shared_value,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api_key(apiKey=key1["id"])))

    before_keys = {item["id"] for item in apigw.get_api_keys(nameQuery=key1["name"])["items"]}
    assert before_keys == {key1["id"]}, f"expected only {key1['id']!r}, got {before_keys!r}"

    code, message = _error(
        lambda: apigw.create_api_key(
            name=ctx.unique_name("sim2real-apikey2-"),
            enabled=True,
            value=shared_value,
            tags={"sim2real": CHECK},
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == "API Key already exists", f"unexpected message {message!r}"

    # The rejected call must not have created a second key sharing the same name-space.
    after_keys = {item["id"] for item in apigw.get_api_keys(nameQuery=key1["name"])["items"]}
    assert after_keys == before_keys, f"expected {before_keys!r} unchanged, got {after_keys!r}"

    # Positive control: a distinct value is accepted and produces a genuinely new key.
    distinct_value = f"sim2realDupKeyOtherValue{suffix}"
    key2 = apigw.create_api_key(
        name=ctx.unique_name("sim2real-apikey3-"),
        enabled=True,
        value=distinct_value,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api_key(apiKey=key2["id"])))
    assert key2["id"] != key1["id"], f"expected a distinct id, got {key2['id']!r} == {key1['id']!r}"
    got_value = apigw.get_api_key(apiKey=key2["id"], includeValue=True)["value"]
    assert got_value == distinct_value, f"expected {distinct_value!r}, got {got_value!r}"

    # Restore leg: the conflict is state (an existing key holding the value), not a
    # malformed input, so removing that state must free the value for reuse.
    apigw.delete_api_key(apiKey=key1["id"])
    gone_code, message = _error(lambda: apigw.get_api_key(apiKey=key1["id"]))
    assert gone_code == "NotFoundException", f"expected NotFoundException, got {gone_code!r}"
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"

    key3 = apigw.create_api_key(
        name=ctx.unique_name("sim2real-apikey4-"),
        enabled=True,
        value=shared_value,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api_key(apiKey=key3["id"])))
    restored_value = apigw.get_api_key(apiKey=key3["id"], includeValue=True)["value"]
    assert restored_value == shared_value, f"expected {shared_value!r}, got {restored_value!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected success raises, so
    accepted input is reported as accepted rather than as a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
