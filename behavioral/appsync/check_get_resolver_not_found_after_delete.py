"""get-resolver-not-found-after-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-resolver-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResolver on a resolver that has been deleted returns NotFoundException, proving the
    resolver's state is fully removed rather than soft-deleted / lingering."""
    client = ctx.client("appsync")

    api_id = client.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: client.delete_graphql_api(apiId=api_id))

    schema = b"type Query { ping: String }\nschema { query: Query }\n"
    client.start_schema_creation(apiId=api_id, definition=schema)
    _wait_for_schema_active(ctx, api_id)

    client.create_data_source(apiId=api_id, name="none_ds", type="NONE")

    client.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName="none_ds",
        requestMappingTemplate='{"version": "2017-02-28", "payload": {}}',
        responseMappingTemplate="$util.toJson($context.result)",
    )

    # positive control: resolver is retrievable right after creation.
    got = client.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    assert got["resolver"]["dataSourceName"] == "none_ds", (
        f"expected dataSourceName='none_ds' on the just-created resolver, got {got['resolver'].get('dataSourceName')!r}"
    )

    client.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")

    # a mutation on the dead id also fails: deleting the already-deleted resolver
    # again must not silently succeed.
    redelete_code, redelete_message = _error(
        lambda: client.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    )
    assert redelete_code == "NotFoundException", (
        f"expected NotFoundException on re-delete of an already-deleted resolver, got {redelete_code!r}"
    )
    assert redelete_message == "No resolver found.", (
        f"unexpected NotFoundException message {redelete_message!r}"
    )

    # terminal assertion: an independent read at the destination, through a different
    # operation than either delete, confirms the resolver's state is fully gone.
    code, message = _error(
        lambda: client.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "No resolver found.", f"unexpected NotFoundException message {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_schema_active(ctx, api_id: str, timeout_s: float = 60.0) -> None:
    client = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = client.get_schema_creation_status(apiId=api_id)["status"]
        if last_status in ("ACTIVE", "SUCCESS"):
            return
        if last_status == "FAILED":
            raise AssertionError("schema creation FAILED while waiting for ACTIVE")
        time.sleep(1.0)
    raise AssertionError(f"schema never became ACTIVE, last status={last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
