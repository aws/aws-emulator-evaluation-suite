"""op-contract-listApiKeys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listApiKeys"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApiKeys reflects created keys; a malformed apiId yields BadRequestException."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    created = appsync.create_api_key(apiId=api_id, description="sim2real-behavioral-key")["apiKey"]

    keys = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert len(keys) == 1, f"expected exactly 1 api key, got {len(keys)}"
    assert keys[0]["id"] == created["id"]
    assert keys[0]["description"] == "sim2real-behavioral-key"
    assert keys[0]["expires"] == created["expires"]

    # AppSync validates the apiId's shape before checking existence. Real
    # apiIds follow an internal format that is stricter than "any
    # lowercase-hex string of the same length" -- even a random same-length
    # hex string fails that shape validation on real AWS and yields
    # BadRequestException, not NotFoundException (NotFoundException is only
    # returned for well-formed-but-nonexistent apiIds, which is impractical
    # to construct without an internal id generator). Assert the actual,
    # observed real-AWS behavior for a malformed apiId.
    import random

    alphabet = "0123456789abcdef"
    bogus_api_id = api_id
    while bogus_api_id == api_id:
        bogus_api_id = "".join(random.choice(alphabet) for _ in api_id)
    code, msg = _error(lambda: appsync.list_api_keys(apiId=bogus_api_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert msg == f"Invalid API ID {bogus_api_id}", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
