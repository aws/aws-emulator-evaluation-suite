"""op-contract-getSchemaCreationStatus."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getSchemaCreationStatus"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSchemaCreationStatus tracks a real schema creation to a terminal state; a bogus apiId 404s."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    appsync.start_schema_creation(
        apiId=api_id, definition=b"type Query {\n  hello: String\n}\n"
    )

    seen_statuses = []
    deadline = time.monotonic() + 90.0
    terminal = None
    while time.monotonic() < deadline:
        resp = appsync.get_schema_creation_status(apiId=api_id)
        seen_statuses.append(resp["status"])
        if resp["status"] in ("SUCCESS", "ACTIVE", "FAILED"):
            terminal = resp
            break
        time.sleep(2)

    assert terminal is not None, f"schema creation never reached a terminal state: {seen_statuses}"
    assert terminal["status"] in ("SUCCESS", "ACTIVE"), f"unexpected terminal status: {terminal}"

    for _ in range(2):
        reread = appsync.get_schema_creation_status(apiId=api_id)["status"]
        assert reread == terminal["status"], (
            f"a read advanced the terminal state: was {terminal['status']!r}, now {reread!r}"
        )

    code, msg = _error(lambda: appsync.get_schema_creation_status(apiId="does_not_exist_1234"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "API not found.", f"unexpected message: {msg!r}"


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
        name=name, authenticationType="API_KEY", tags={"sim2real-check": CHECK}
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
