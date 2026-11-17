"""create-api-key-description-presence-matches-input."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-api-key-description-presence-matches-input"
GROUP = "api-keys"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey with no description leaves the field absent on create and on ListApiKeys;
    a sibling key created with a description keeps exactly that value in both places."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    bare = appsync.create_api_key(apiId=api_id)["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=bare["id"]))
    assert "description" not in bare, (
        f"description was absent from the request but present on create: {bare!r}"
    )

    description = f"Key for {ctx.unique_name('sim2real-appsync')}.example.com"
    described = appsync.create_api_key(apiId=api_id, description=description)["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=described["id"]))
    assert described["description"] == description, (
        f"expected description {description!r} on create, got {described.get('description')!r}"
    )

    by_id = {k["id"]: k for k in appsync.list_api_keys(apiId=api_id)["apiKeys"]}
    bare_listed = by_id[bare["id"]]
    assert "description" not in bare_listed, (
        f"description was absent on create but present in ListApiKeys: {bare_listed!r}"
    )

    described_listed = by_id[described["id"]]
    assert described_listed["description"] == description, (
        f"expected description {description!r} in ListApiKeys, got "
        f"{described_listed.get('description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
