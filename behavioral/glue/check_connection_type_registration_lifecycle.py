"""connection-type-registration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-type-registration-lifecycle"
GROUP = "connection"
SERVICES = ["glue"]


def _error_code(fn) -> str:
    """The Error.Code ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterConnectionType creates a custom REST connection type that DescribeConnectionType
    reads back and ListConnectionTypes surfaces, rejects a duplicate registration, and
    DeleteConnectionType removes it so neither surface finds it again.
    """
    glue = ctx.client("glue")

    connection_type_name = "REST-" + ctx.unique_name("SIM2REAL-BEHAV-CONNTYPE-").upper().replace("_", "-")
    url_property = {
        "Name": "Url", "Required": True, "PropertyType": "USER_INPUT", "PropertyLocation": "HEADER",
    }
    username_property = {
        "Name": "Username", "Required": True, "PropertyType": "SECRET", "PropertyLocation": "HEADER",
    }
    password_property = {
        "Name": "Password", "Required": True, "PropertyType": "SECRET", "PropertyLocation": "HEADER",
    }
    glue.register_connection_type(
        ConnectionType=connection_type_name,
        IntegrationType="REST",
        Description="a check-owned custom REST connection type",
        ConnectionProperties={"Url": url_property},
        ConnectorAuthenticationConfiguration={
            "AuthenticationTypes": ["BASIC"],
            "BasicAuthenticationProperties": {"Username": username_property, "Password": password_property},
        },
        RestConfiguration={},
    )
    ctx.on_cleanup(_teardown(
        lambda: glue.delete_connection_type(ConnectionType=connection_type_name), "EntityNotFoundException"
    ))

    described = glue.describe_connection_type(ConnectionType=connection_type_name)
    assert described["ConnectionType"] == connection_type_name, (
        f"DescribeConnectionType returned a different type: {described['ConnectionType']!r}"
    )
    assert described["Description"] == "a check-owned custom REST connection type", (
        f"DescribeConnectionType Description mismatch: {described['Description']!r}"
    )
    assert described["Capabilities"]["SupportedAuthenticationTypes"] == ["BASIC"], (
        f"DescribeConnectionType did not echo the authentication type: {described['Capabilities']!r}"
    )
    assert described["ConnectionProperties"]["URL"]["Required"] is True, (
        f"DescribeConnectionType did not echo the Url property as required: "
        f"{described['ConnectionProperties'].get('URL')!r}"
    )

    names = set()
    for page in glue.get_paginator("list_connection_types").paginate():
        names.update(ct["ConnectionType"] for ct in page["ConnectionTypes"])
    assert connection_type_name in names, f"ListConnectionTypes did not include {connection_type_name!r}"

    # negative: registering the identical type name again is rejected
    code, msg = _error(lambda: glue.register_connection_type(
        ConnectionType=connection_type_name,
        IntegrationType="REST",
        ConnectionProperties={"Url": url_property},
        ConnectorAuthenticationConfiguration={
            "AuthenticationTypes": ["BASIC"],
            "BasicAuthenticationProperties": {"Username": username_property, "Password": password_property},
        },
        RestConfiguration={},
    ))
    assert code == "AlreadyExistsException", f"re-registering an existing connection type name gave {code!r}"
    assert msg == f"Connection type already exists: {connection_type_name}", f"unexpected message: {msg!r}"

    # delete proves gone: the type no longer answers Describe or appears in the listing
    glue.delete_connection_type(ConnectionType=connection_type_name)
    code_describe = _error_code(lambda: glue.describe_connection_type(ConnectionType=connection_type_name))
    assert code_describe == "InvalidInputException", f"describing a deleted connection type gave {code_describe!r}"
    names_after = set()
    for page in glue.get_paginator("list_connection_types").paginate():
        names_after.update(ct["ConnectionType"] for ct in page["ConnectionTypes"])
    assert connection_type_name not in names_after, (
        f"ListConnectionTypes still lists a deleted connection type {connection_type_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
