"""start-schema-creation-builtin-scalar-matrix-or-failed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-schema-creation-builtin-scalar-matrix-or-failed"
GROUP = "schema-creation"
SERVICES = ["appsync"]

_UNDECLARED_SCALAR = "AWSMacAddress"
_TYPE_NOT_FOUND = ("NotFoundException", "Type not found.")

# Every AppSync service-defined scalar, each mapped to a field name of its own.
_FIELDS = (
    ("birthday", "AWSDate"),
    ("curfew", "AWSTime"),
    ("checkin", "AWSDateTime"),
    ("epoch", "AWSTimestamp"),
    ("sender", "AWSEmail"),
    ("payload", "AWSJSON"),
    ("hotline", "AWSPhone"),
    ("homepage", "AWSURL"),
    ("origin", "AWSIPAddress"),
)


def _sdl(fields) -> str:
    body = "\n".join(f"  {name}: {scalar}" for name, scalar in fields)
    return f"type Query {{\n{body}\n}}\n"


def _compiled_sdl(fields) -> str:
    """The exact form GetType returns for a Query type compiled from ``fields``."""
    body = "\n\n\n".join(f"{name}: {scalar}" for name, scalar in fields)
    return f"type Query\n\n{{\n{body}\n\n}}\n"


def _teardown(undo, *not_found: str):
    """A cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _poll_terminal(probe, *, timeout_s=90.0, interval_s=2.0, description="schema creation"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last["status"] in ("SUCCESS", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not reach a terminal status within {timeout_s}s: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSchemaCreation with every AppSync built-in scalar reaches SUCCESS and GetType
    returns the exact compiled SDL; the same schema with one scalar swapped for an undeclared
    type name reaches FAILED with the exact recorded failure details, and the type is absent."""
    appsync = ctx.client("appsync")

    control_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-scalars-ok-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(_teardown(lambda: appsync.delete_graphql_api(apiId=control_api["apiId"]), "NotFoundException"))
    control_api_id = control_api["apiId"]

    control_start = appsync.start_schema_creation(apiId=control_api_id, definition=_sdl(_FIELDS))
    assert control_start["status"] == "PROCESSING", (
        f"expected StartSchemaCreation to return PROCESSING, got {control_start['status']!r}"
    )

    control_final = _poll_terminal(
        lambda: appsync.get_schema_creation_status(apiId=control_api_id),
        description="control schema creation (every built-in scalar)",
    )
    assert control_final["status"] == "SUCCESS", (
        f"expected the full built-in scalar matrix to reach SUCCESS, got {control_final!r}"
    )
    assert control_final["details"] == "Successfully created schema with 1 types.", (
        f"unexpected success details: {control_final['details']!r}"
    )

    got_type = appsync.get_type(apiId=control_api_id, typeName="Query", format="SDL")["type"]
    expected_sdl = _compiled_sdl(_FIELDS)
    assert got_type["definition"] == expected_sdl, (
        f"compiled SDL did not match; expected {expected_sdl!r}, got {got_type['definition']!r}"
    )

    broken_fields = list(_FIELDS[:-1]) + [(_FIELDS[-1][0], _UNDECLARED_SCALAR)]
    broken_api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-scalars-bad-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(_teardown(lambda: appsync.delete_graphql_api(apiId=broken_api["apiId"]), "NotFoundException"))
    broken_api_id = broken_api["apiId"]

    broken_start = appsync.start_schema_creation(apiId=broken_api_id, definition=_sdl(broken_fields))
    assert broken_start["status"] == "PROCESSING", (
        f"expected StartSchemaCreation to return PROCESSING, got {broken_start['status']!r}"
    )

    broken_final = _poll_terminal(
        lambda: appsync.get_schema_creation_status(apiId=broken_api_id),
        description="broken schema creation (undeclared scalar)",
    )
    assert broken_final["status"] == "FAILED", (
        f"expected the undeclared-scalar swap to reach FAILED, got {broken_final!r}"
    )
    expected_details = (
        f"Found 1 problem(s) with the schema:\n"
        f"The field type '{_UNDECLARED_SCALAR}' is not present when resolving type 'Query'."
    )
    assert broken_final["details"] == expected_details, (
        f"unexpected failure details; expected {expected_details!r}, got {broken_final['details']!r}"
    )

    expect_error(
        lambda: appsync.get_type(apiId=broken_api_id, typeName="Query", format="SDL"),
        *_TYPE_NOT_FOUND,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
