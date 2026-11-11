"""op-contract-delete-resolver."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-resolver"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResolver removes the resolver; GetResolver then 404s and a repeat delete is rejected."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api_with_schema(ctx)
    ds_name = ctx.unique_name("sim2real_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )

    # Positive control: the resolver is retrievable right after creation, so the
    # later NotFoundException is caused by the delete, not by a create that never
    # took effect.
    before = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    assert before["resolver"]["dataSourceName"] == ds_name, (
        f"expected resolver bound to {ds_name!r} before delete, "
        f"got {before['resolver'].get('dataSourceName')!r}"
    )

    appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")

    code, code_msg = _error(
        lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException after delete, got {code}"
    )
    assert code_msg == "No resolver found.", f"unexpected message: {code_msg!r}"

    # Error boundary: deleting the same resolver again -> NotFoundException.
    code, code_msg = _error(
        lambda: appsync.delete_resolver(
            apiId=api_id, typeName="Query", fieldName="ping"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == "No resolver found.", f"unexpected message: {code_msg!r}"

    # Reusability: the (typeName, fieldName) identifier is released by the delete,
    # not soft-locked, so it can be bound to a resolver again.
    recreated = appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName=ds_name,
        kind="UNIT",
        requestMappingTemplate="{}",
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    assert recreated["resolver"]["dataSourceName"] == ds_name, (
        "expected recreated resolver to bind to the same data source, "
        f"got {recreated['resolver'].get('dataSourceName')!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_graphql_api_with_schema(ctx) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"), authenticationType="API_KEY"
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    definition = b"schema { query: Query }\ntype Query { ping: String }\n"
    appsync.start_schema_creation(apiId=api_id, definition=definition)
    deadline = time.monotonic() + 60.0
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_schema_creation_status(apiId=api_id)["status"]
        if status in ("ACTIVE", "SUCCESS", "FAILED"):
            break
        time.sleep(2)
    assert status in ("ACTIVE", "SUCCESS"), f"schema creation ended in status={status}"
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
