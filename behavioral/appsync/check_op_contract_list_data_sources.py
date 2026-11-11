"""op-contract-listDataSources."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listDataSources"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSources reflects every created data source; a malformed apiId yields BadRequestException."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    name_a = ctx.unique_name("sim2real_ds_a_").replace("-", "_")
    name_b = ctx.unique_name("sim2real_ds_b_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=name_a, type="NONE")
    appsync.create_data_source(apiId=api_id, name=name_b, type="NONE")

    data_sources = appsync.list_data_sources(apiId=api_id)["dataSources"]
    names = {ds["name"] for ds in data_sources}
    assert {name_a, name_b}.issubset(names), f"expected {name_a},{name_b} in {names}"
    assert len(data_sources) == 2, f"expected exactly 2 data sources, got {len(data_sources)}: {names}"

    # AppSync validates the apiId's shape before checking existence: a
    # random same-length hex string fails that shape validation on real AWS
    # and yields BadRequestException, not NotFoundException. (A
    # well-formed-but-nonexistent apiId, e.g. one just deleted, is a
    # different error boundary covered elsewhere in this suite.)
    import random

    alphabet = "0123456789abcdef"
    bogus_api_id = api_id
    while bogus_api_id == api_id:
        bogus_api_id = "".join(random.choice(alphabet) for _ in api_id)
    code, message = _error_code(lambda: appsync.list_data_sources(apiId=bogus_api_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected_message = f"Invalid API ID {bogus_api_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real-owner": "behavioral-check"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
