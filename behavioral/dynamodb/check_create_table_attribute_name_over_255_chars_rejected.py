"""create-table-attribute-name-over-255-chars-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-attribute-name-over-255-chars-rejected"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]

_AT_LIMIT = "k" * 255
_OVER_LIMIT = "k" * 256


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CreateTable accepts a 255-character attribute name and rejects a 256-character one
    with ValidationException naming both the KeySchema and AttributeDefinitions members.
    """
    ddb = ctx.client("dynamodb")

    at_limit_table = ctx.unique_name("sim2real-behav-attrlen-ok-")
    ddb.create_table(
        TableName=at_limit_table,
        KeySchema=[{"AttributeName": _AT_LIMIT, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": _AT_LIMIT, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=at_limit_table))
    ddb.get_waiter("table_exists").wait(
        TableName=at_limit_table, WaiterConfig={"Delay": 2, "MaxAttempts": 250}
    )
    desc = ddb.describe_table(TableName=at_limit_table)["Table"]
    got_name = desc["KeySchema"][0]["AttributeName"]
    assert got_name == _AT_LIMIT, (
        f"a 255-character attribute name was not preserved, got a name of length {len(got_name)}"
    )

    over_limit_table = ctx.unique_name("sim2real-behav-attrlen-bad-")

    def bad_create():
        ddb.create_table(
            TableName=over_limit_table,
            KeySchema=[{"AttributeName": _OVER_LIMIT, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": _OVER_LIMIT, "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

    code, message = _error(bad_create)
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        f"2 validation errors detected: Value '{_OVER_LIMIT}' at "
        f"'keySchema.1.member.attributeName' failed to satisfy constraint: Member must have "
        f"length less than or equal to 255; Value '{_OVER_LIMIT}' at "
        f"'attributeDefinitions.1.member.attributeName' failed to satisfy constraint: Member "
        f"must have length less than or equal to 255"
    )
    assert message == expected, f"unexpected message {message!r}"

    code, _ = _error(lambda: ddb.describe_table(TableName=over_limit_table))
    assert code == "ResourceNotFoundException", (
        f"the rejected CreateTable must not have created {over_limit_table!r}, got {code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
