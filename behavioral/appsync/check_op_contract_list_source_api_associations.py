"""op-contract-listSourceApiAssociations."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listSourceApiAssociations"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSourceApiAssociations on a plain (non-merged) GraphQL API returns an empty association list; a bogus (malformed) apiId is rejected with BadRequestException."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, appsync)

    resp = appsync.list_source_api_associations(apiId=api_id)
    assert resp["sourceApiAssociationSummaries"] == [], (
        f"expected no source API associations on a freshly created API, got {resp['sourceApiAssociationSummaries']}"
    )
    assert "nextToken" not in resp or resp.get("nextToken") is None, (
        f"expected no pagination token for an empty association list, got {resp.get('nextToken')!r}"
    )

    bogus_api_id = "bogus_api_id_00000"
    code, message = _error_code(lambda: appsync.list_source_api_associations(apiId=bogus_api_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected_message = f"Invalid API ID {bogus_api_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, appsync):
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": "behavioral"}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
