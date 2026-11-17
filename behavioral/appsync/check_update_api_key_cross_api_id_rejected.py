"""update-api-key-cross-api-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-api-key-cross-api-id-rejected"
GROUP = "api-keys"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey refuses a key id scoped to a different GraphQL API with NotFoundException,
    and leaves its description unchanged, while the same update on its own API succeeds."""
    appsync = ctx.client("appsync")
    owner_api = _create_graphql_api(ctx, "owner")
    owner_api_id = owner_api["apiId"]
    other_api = _create_graphql_api(ctx, "other")
    other_api_id = other_api["apiId"]

    original = f"Key for {ctx.unique_name('sim2real-appsync')}.example.com"
    key = appsync.create_api_key(apiId=owner_api_id, description=original)["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=owner_api_id, id=key["id"]))

    attempted = f"Key for {ctx.unique_name('sim2real-appsync')}.invalid"
    code, message = _error(
        lambda: appsync.update_api_key(
            apiId=other_api_id, id=key["id"], description=attempted
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    expected_message = f"API key not found: {key['id']}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    unchanged = next(
        k for k in appsync.list_api_keys(apiId=owner_api_id)["apiKeys"] if k["id"] == key["id"]
    )
    assert unchanged["description"] == original, (
        f"the refused update changed the description to {unchanged['description']!r}, "
        f"expected it to stay {original!r}"
    )

    updated = f"Key for {ctx.unique_name('sim2real-appsync')}.test"
    own_update = appsync.update_api_key(
        apiId=owner_api_id, id=key["id"], description=updated
    )["apiKey"]
    assert own_update["description"] == updated, (
        f"expected description {updated!r} after updating on its own API, got "
        f"{own_update['description']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_graphql_api(ctx, suffix):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name(f"sim2real-behav-{suffix}-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
