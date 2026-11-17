"""test-connection-rejects-incomplete-jdbc-properties."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-connection-rejects-incomplete-jdbc-properties"
GROUP = "connection"
SERVICES = ["glue"]


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestConnection rejects an inline JDBC TestConnectionInput outright, and rejects an
    inline SALESFORCE TestConnectionInput missing the OAuth2 properties its type requires,
    each with its own distinct code and message.
    """
    glue = ctx.client("glue")

    code1, msg1 = _error(lambda: glue.test_connection(
        TestConnectionInput={
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": "jdbc:mysql://198.51.100.10:3306/exampledb",
                "USERNAME": "example-user",
                "PASSWORD": "example-password",
            },
        }
    ))
    assert code1 == "ValidationException", f"an inline JDBC TestConnectionInput gave {code1!r}"
    assert msg1 == "TestConnection is only supported for the Unified Connections", (
        f"unexpected message: {msg1!r}"
    )

    code2, msg2 = _error(lambda: glue.test_connection(
        TestConnectionInput={
            "ConnectionType": "SALESFORCE",
            "ConnectionProperties": {},
            "AuthenticationConfiguration": {"AuthenticationType": "OAUTH2"},
        }
    ))
    assert code2 == "InvalidInputException", f"an incomplete SALESFORCE TestConnectionInput gave {code2!r}"
    assert msg2 == "[AuthenticationConfiguration.OAuth2Properties is required for OAUTH2 AuthenticationType.]", (
        f"unexpected message: {msg2!r}"
    )
    assert code2 != code1, "a JDBC-only restriction and a SALESFORCE field-level validation produced the same code"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
