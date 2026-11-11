"""execute-statement-literal-leading-dot-with-no-mantissa-digit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-literal-leading-dot-with-no-mantissa-digit-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_UNEXPECTED_TERM_MESSAGE = "Statement wasn't well formed, can't be processed: Unexpected term"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A leading-dot number literal with no mantissa digit at all, just a dot immediately
    followed by an exponent marker, is rejected, while a leading-dot literal that carries a
    mantissa digit is accepted and canonicalized.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.insert.html
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # Positive control: a leading-dot literal that carries a mantissa digit is accepted and
    # canonicalized with the implied leading zero filled in.
    ddb.execute_statement(Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'ctrl', 'n': .5}}")
    control = ddb.get_item(TableName=table_name, Key={"pk": {"S": "ctrl"}}, ConsistentRead=True)["Item"]
    assert control["n"] == {"N": "0.5"}, f"literal .5 must store as canonical N 0.5, got {control['n']!r}"

    # A leading dot with no digit anywhere in the mantissa is rejected at the lexical level.
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f"INSERT INTO \"{table_name}\" VALUE {{'pk': 'bad', 'n': .e5}}"
    ))
    assert code == ERR_VALIDATION, f"a mantissa-less leading dot must be {ERR_VALIDATION}, got {code!r}"
    assert message == _UNEXPECTED_TERM_MESSAGE, f"expected AWS's exact message, got {message!r}"
    leaked = ddb.get_item(TableName=table_name, Key={"pk": {"S": "bad"}}, ConsistentRead=True)
    assert "Item" not in leaked, f"the rejected INSERT must not have written an item, found {leaked.get('Item')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
