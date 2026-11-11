"""op-contract-delete-type."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-type"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteType removes the type; GetType then 404s, a second DeleteType on the same
    now-dead type 404s, and deleting a type that never existed 404s too."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    definition = "type Foo {\n  id: ID!\n}\n"
    created = appsync.create_type(apiId=api_id, definition=definition, format="SDL")[
        "type"
    ]
    type_name = created["name"]
    assert type_name == "Foo", f"expected created type named Foo, got {type_name!r}"

    appsync.delete_type(apiId=api_id, typeName=type_name)

    code, code_msg = _error(
        lambda: appsync.get_type(apiId=api_id, typeName=type_name, format="SDL")
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException after delete, got {code}"
    )
    assert code_msg == "Type not found.", f"unexpected message: {code_msg!r}"

    # Error boundary: deleting the same type again (it is now dead) -> NotFoundException.
    code, code_msg = _error(
        lambda: appsync.delete_type(apiId=api_id, typeName=type_name)
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException on double delete, got {code}"
    )
    assert code_msg == "Type not found.", f"unexpected message: {code_msg!r}"

    # Distinct error boundary: deleting a type that never existed -> NotFoundException.
    code, code_msg = _error(
        lambda: appsync.delete_type(apiId=api_id, typeName="NeverExisted")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert code_msg == "Type not found.", f"unexpected message: {code_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"), authenticationType="API_KEY"
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
