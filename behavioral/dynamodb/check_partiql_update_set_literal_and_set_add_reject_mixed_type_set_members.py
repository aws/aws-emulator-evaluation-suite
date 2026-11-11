"""partiql-update-set-literal-and-set-add-reject-mixed-type-set-members."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-set-literal-and-set-add-reject-mixed-type-set-members"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_MIXED_LITERAL = (
    "ValidationException",
    "Unsupported data type in Bag. DynamoDB only supports either numbers or strings in bags",
)
_MIXED_OPERAND = (
    "ValidationException",
    "An operand in the update expression has an incorrect data type",
)


def _wait_table_active(ctx, ddb, table_name):
    """Poll DescribeTable until TableStatus is ACTIVE, bounded by the run's remaining time."""
    left = ctx.time_left()
    budget_s = 90.0 if left is None else max(5.0, min(90.0, left - 10.0))
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)['Table']
        if last['TableStatus'] == 'ACTIVE':
            return last
        time.sleep(1.0)
    raise AssertionError(f'table {table_name} never went ACTIVE in {budget_s}s: {last!r}')


def _expect_error(fn, code, message):
    """Call fn() and assert the ClientError it raises carries exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        got = (err.get('Code'), err.get('Message'))
        assert got == (code, message), f'expected {(code, message)!r}, got {got!r}'
        return exc
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATE ... SET on a mixed-type set literal, and set_add() mixing a member of a different
    type into an existing set, are both refused and leave the set unchanged; UPDATE ... SET on a
    mixed-type list or map literal succeeds and stores each element with its own type.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    _wait_table_active(ctx, ddb, t)

    nonce = ctx.unique_name('doc-')
    key = {'pk': {'S': nonce}}

    def _stored():
        return ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']

    # Seed the item with a homogeneous String Set literal (positive control).
    ddb.execute_statement(
        Statement=f"INSERT INTO \"{t}\" VALUE {{'pk': ?, 'goodset': <<'x', 'y'>>}}",
        Parameters=[{'S': nonce}],
    )
    item = _stored()
    assert set(item['goodset']['SS']) == {'x', 'y'}, (
        f"seeded item must have goodset {{'x','y'}}, got {item.get('goodset')!r}"
    )

    # Negative 1: UPDATE ... SET on a mixed-type (number, string) set literal is refused, and the
    # set stays exactly as seeded.
    _expect_error(
        lambda: ddb.execute_statement(
            Statement=f"UPDATE \"{t}\" SET goodset = <<1, 'z'>> WHERE pk = ?",
            Parameters=[{'S': nonce}],
        ),
        *_MIXED_LITERAL,
    )
    item = _stored()
    assert set(item['goodset']['SS']) == {'x', 'y'}, (
        f"goodset must be unchanged after the refused literal UPDATE, got {item.get('goodset')!r}"
    )

    # Negative 2: set_add() mixing a Number into an existing String Set is refused with the
    # operand-type message, and the set is unchanged.
    _expect_error(
        lambda: ddb.execute_statement(
            Statement=f"UPDATE \"{t}\" SET goodset = set_add(goodset, <<5>>) WHERE pk = ?",
            Parameters=[{'S': nonce}],
        ),
        *_MIXED_OPERAND,
    )
    item = _stored()
    assert set(item['goodset']['SS']) == {'x', 'y'}, (
        f"goodset must be unchanged after the refused set_add, got {item.get('goodset')!r}"
    )

    # Positive: UPDATE ... SET on a mixed-type list and a mixed-type map literal succeeds, and
    # each element stores with its own type exactly as written.
    ddb.execute_statement(
        Statement=(
            f"UPDATE \"{t}\" SET mixedlist = [1, 'a', true], mixedmap = {{'a':1,'b':'x'}} "
            f"WHERE pk = ?"
        ),
        Parameters=[{'S': nonce}],
    )
    item = _stored()
    assert item['mixedlist'] == {'L': [{'N': '1'}, {'S': 'a'}, {'BOOL': True}]}, (
        f"mixedlist must store [N,S,BOOL] in order, got {item.get('mixedlist')!r}"
    )
    assert item['mixedmap'] == {'M': {'a': {'N': '1'}, 'b': {'S': 'x'}}}, (
        f"mixedmap must store {{a:N, b:S}}, got {item.get('mixedmap')!r}"
    )
    assert set(item['goodset']['SS']) == {'x', 'y'}, (
        f"goodset must still be unchanged after the unrelated SET, got {item.get('goodset')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
