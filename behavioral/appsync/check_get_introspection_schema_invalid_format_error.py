"""get-introspection-schema-invalid-format-error."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-introspection-schema-invalid-format-error"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIntrospectionSchema with a format outside SDL|JSON fails BadRequestException on an API with
    an active schema, while a valid format returns the schema text."""
    client = ctx.client("appsync")

    api_id = client.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: client.delete_graphql_api(apiId=api_id))

    schema = b"type Query { hello: String }\nschema { query: Query }\n"
    client.start_schema_creation(apiId=api_id, definition=schema)
    _wait_for_schema_active(ctx, api_id)

    # positive control: a supported format on a genuinely active schema returns real SDL text.
    good = client.get_introspection_schema(apiId=api_id, format="SDL")
    sdl_text = good["schema"].read().decode("utf-8")
    assert "hello" in sdl_text and "Query" in sdl_text, sdl_text

    # negative: an unsupported format string is rejected as a client-input validation error.
    code, message = _error(
        lambda: client.get_introspection_schema(apiId=api_id, format="YAML")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid format YAML given", f"unexpected BadRequestException message {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a client error, but the call SUCCEEDED and returned {result!r}")


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
