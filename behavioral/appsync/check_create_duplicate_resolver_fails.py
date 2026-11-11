"""create-duplicate-resolver-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-resolver-fails"
GROUP = 'resolver'
SERVICES = ['appsync']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second resolver for the same typeName+fieldName must fail with
    BadRequestException, must leave the original resolver's mapping template untouched, and the
    identical call must succeed once the conflicting resolver is deleted."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)["apiId"]
    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    appsync.create_data_source(apiId=api_id, name=ds_name, type="NONE")

    appsync.start_schema_creation(apiId=api_id, definition=b"type Query { ping: String }")
    _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=60,
        interval_s=2,
    )

    appsync.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="ping",
        dataSourceName=ds_name,
        requestMappingTemplate='{"version": "2017-02-28"}',
        responseMappingTemplate='"pong"',
    )

    def _dup():
        return appsync.create_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="ping",
            dataSourceName=ds_name,
            requestMappingTemplate='{"version": "2017-02-28"}',
            responseMappingTemplate='"pong2"',
        )

    code, message = _error(_dup)
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Only one resolver is allowed per field.", f"expected the exact refusal message, got {message!r}"

    unchanged = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")["resolver"]
    assert unchanged["responseMappingTemplate"] == '"pong"', (
        "rejected duplicate must leave the original resolver untouched, "
        f"got responseMappingTemplate={unchanged['responseMappingTemplate']!r}"
    )

    appsync.delete_resolver(apiId=api_id, typeName="Query", fieldName="ping")
    _dup()
    restored = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ping")["resolver"]
    assert restored["responseMappingTemplate"] == '"pong2"', (
        "the identical call must succeed once the conflicting resolver is gone, "
        f"got responseMappingTemplate={restored['responseMappingTemplate']!r}"
    )


def _create_graphql_api(ctx) -> dict:
    """An API_KEY-auth GraphQL API. Sub-resources (data sources, functions,
    resolvers, types) are removed with their owning apiId, so only the API
    itself needs a teardown."""
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
