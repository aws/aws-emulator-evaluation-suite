"""delete-alias-removes-it."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-alias-removes-it"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteAlias, DescribeAlias and UpdateAlias on the deleted AliasId fail with NotFoundException and
    the alias's exact message, and ListAliases does not return it.
    """
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-alias-del-")
    alias_id = gl.create_alias(
        Name=name,
        RoutingStrategy={"Type": "TERMINAL", "Message": "to be deleted"},
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )["Alias"]["AliasId"]
    ctx.on_cleanup(lambda: _delete_if_present(gl, alias_id))

    # Sanity: it exists before deletion.
    gl.describe_alias(AliasId=alias_id)

    gl.delete_alias(AliasId=alias_id)

    code, message = _error(lambda: gl.describe_alias(AliasId=alias_id))
    assert code == "NotFoundException", f"expected NotFoundException describing a deleted alias, got {code!r}"
    expected_message = f"Alias ({alias_id}) not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    remaining = gl.list_aliases(Name=name)["Aliases"]
    assert all(a["AliasId"] != alias_id for a in remaining), (
        f"deleted alias {alias_id} must not reappear in ListAliases, got {remaining!r}"
    )

    update_code, update_message = _error(
        lambda: gl.update_alias(
            AliasId=alias_id, RoutingStrategy={"Type": "TERMINAL", "Message": "resurrected"}
        )
    )
    assert update_code == "NotFoundException", (
        f"a mutation (UpdateAlias) against a deleted alias must fail NotFoundException, got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_if_present(gl, alias_id):
    from botocore.exceptions import ClientError

    try:
        gl.delete_alias(AliasId=alias_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
