"""execute-statement-insert-parameter-nesting-depth-32-levels-accepted-33-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-insert-parameter-nesting-depth-32-levels-accepted-33-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _nest(levels: int):
    """A chain of `levels` maps around one scalar leaf, `levels + 1` levels deep in total."""
    value = {"S": "leaf"}
    for _ in range(levels):
        value = {"M": {"k": value}}
    return value


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore error code and message `fn` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement's INSERT INTO ... VALUE accepts a 32-level nested Map parameter and
    rejects a 33-level one with ValidationException, the same depth limit PutItem enforces, and
    the rejected row is not written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Limits.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlnest-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    def read(pk: str):
        return ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}" WHERE pk = ?', Parameters=[{"S": pk}], ConsistentRead=True
        )["Items"]

    # Positive control: 31 wrapping maps + the leaf = 32 levels, the deepest accepted document,
    # bound through a PartiQL INSERT's Parameters list.
    ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'pk\':?, \'v\':?}}',
        Parameters=[{"S": "deepest"}, _nest(31)],
    )
    got = read("deepest")
    assert len(got) == 1, f"the 32-level control row must be written, got {got!r}"
    cursor = got[0]["v"]
    for level in range(31):
        assert cursor is not None and "M" in cursor, (
            f"stored document must preserve all 31 map levels; level {level} was {cursor!r}"
        )
        cursor = cursor["M"].get("k")
    assert cursor == {"S": "leaf"}, f"the leaf at depth 32 must round-trip, got {cursor!r}"

    # One level deeper is 33 and must be refused, with nothing written.
    code, message = _code_and_message(lambda: ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'pk\':?, \'v\':?}}',
        Parameters=[{"S": "too-deep"}, _nest(32)],
    ))
    assert code == ERR_VALIDATION, f"a 33-level INSERT parameter must be {ERR_VALIDATION}, got {code!r}"
    assert message == "Nesting Levels have exceeded supported limits", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert read("too-deep") == [], "a row rejected for nesting depth must not be stored"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
