"""start-schema-creation-conflict-in-progress."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-schema-creation-conflict-in-progress"
GROUP = "error-semantics"
SERVICES = ["appsync"]


# A schema this size keeps the creation job in PROCESSING for seconds on AWS.
_TYPE_COUNT = 300
_SCHEMA = (
    "\n".join(f"type T{i} {{ id: ID! a: String b: Int c: [String] }}" for i in range(_TYPE_COUNT))
    + "\ntype Query { "
    + " ".join(f"t{i}: T{i}" for i in range(_TYPE_COUNT))
    + " }\nschema { query: Query }\n"
).encode()
_CONFLICT_MESSAGE = "Schema is currently being altered, please wait until that is complete."
# AWS counts the declared object types plus Query and one built-in type.
_SUCCESS_DETAILS = f"Successfully created schema with {_TYPE_COUNT + 2} types."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSchemaCreation while the API's prior creation is PROCESSING fails
    ConcurrentModificationException with its exact message; once the job settles to SUCCESS, an
    identical call is accepted again."""
    client = ctx.client("appsync")

    api_id = client.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: client.delete_graphql_api(apiId=api_id))

    first = client.start_schema_creation(apiId=api_id, definition=_SCHEMA)
    assert first["status"] == "PROCESSING", (
        f"expected StartSchemaCreation of the {_TYPE_COUNT}-type schema to answer PROCESSING, got {first}"
    )
    # The conflict holds only while the first job is PROCESSING. GetSchemaCreationStatus, read
    # independently right before the second call, decides its expected outcome: PROCESSING must
    # refuse it, a job already settled to SUCCESS accepts it as a new job.
    status_before = client.get_schema_creation_status(apiId=api_id)["status"]
    assert status_before in ("PROCESSING", "SUCCESS"), (
        f"expected GetSchemaCreationStatus to report PROCESSING or SUCCESS, got {status_before!r}"
    )
    if status_before == "PROCESSING":
        try:
            client.start_schema_creation(apiId=api_id, definition=_SCHEMA)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message")
        else:
            raise AssertionError(
                "a second StartSchemaCreation succeeded with no error while GetSchemaCreationStatus "
                f"read just before reported the {_TYPE_COUNT}-type schema creation PROCESSING for "
                f"api {api_id}: the target does not enforce single-flight schema creation"
            )
        assert code == "ConcurrentModificationException", (
            f"expected ConcurrentModificationException, got {code}"
        )
        assert message == _CONFLICT_MESSAGE, (
            f"expected message {_CONFLICT_MESSAGE!r}, got {message!r}"
        )
    else:
        second = client.start_schema_creation(apiId=api_id, definition=_SCHEMA)
        assert second["status"] == "PROCESSING", (
            f"expected a second StartSchemaCreation accepted after the first settled to answer "
            f"PROCESSING, got {second}"
        )

    settled = _wait_for_schema_settled(ctx, api_id, timeout_s=90.0)
    assert settled["status"] == "SUCCESS", f"expected the winning job to settle to SUCCESS, got {settled}"
    assert settled["details"] == _SUCCESS_DETAILS, (
        f"expected details {_SUCCESS_DETAILS!r}, got {settled.get('details')!r}"
    )

    # Restore leg: once the winning job settles, the identical call must be accepted again --
    # the rejection above was "another job is in flight", not a permanent lock on this API.
    restore_resp = client.start_schema_creation(apiId=api_id, definition=_SCHEMA)
    assert restore_resp["status"] == "PROCESSING", (
        f"expected a new StartSchemaCreation to be accepted as PROCESSING once the prior job settled, got {restore_resp}"
    )
    restored = _wait_for_schema_settled(ctx, api_id, timeout_s=90.0)
    assert restored["status"] == "SUCCESS", (
        f"expected the restored schema creation to settle to SUCCESS, got {restored}"
    )
    assert restored["details"] == _SUCCESS_DETAILS, (
        f"expected details {_SUCCESS_DETAILS!r}, got {restored.get('details')!r}"
    )


def _wait_for_schema_settled(ctx, api_id: str, timeout_s: float) -> dict:
    client = ctx.client("appsync")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = client.get_schema_creation_status(apiId=api_id)
        if resp["status"] != "PROCESSING":
            return {"status": resp["status"], "details": resp.get("details")}
        time.sleep(0.5)
    raise AssertionError(
        f"schema creation for api {api_id} did not leave PROCESSING within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
