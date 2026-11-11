"""scan-filter-begins-with-non-string-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-begins-with-non-string-operand-rejected"
GROUP = 'expressions'
SERVICES = ['dynamodb']

_INVALID_OPERAND_MESSAGE = (
    "Invalid FilterExpression: Incorrect operand type for operator or function; "
    "operator or function: begins_with, operand type: {op_type}"
)


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; RAISES if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_table_active(ddb, ctx, name):
    """Wait for the table to become ACTIVE, bounded by the check's own remaining budget."""
    budget = max(10.0, min(120.0, (ctx.time_left() or 120.0) - 10.0))
    delay = 2
    attempts = max(1, int(budget // delay))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={'Delay': delay, 'MaxAttempts': attempts})


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression refuses begins_with on an N or BOOL operand with
    ValidationException, identically on an empty table and a populated one, and
    scans nothing into existence while doing so.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddb-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    _wait_table_active(ddb, ctx, t)

    def _scan_begins_with(operand_value):
        return ddb.scan(
            TableName=t,
            FilterExpression='begins_with(attr, :v)',
            ExpressionAttributeValues={':v': operand_value},
            ConsistentRead=True,
        )

    for stage in ('empty', 'populated'):
        if stage == 'populated':
            ddb.put_item(TableName=t, Item={'pk': {'S': 'alpha-item'}, 'attr': {'S': 'alphabet'}})
            ddb.put_item(TableName=t, Item={'pk': {'S': 'zeta-item'}, 'attr': {'S': 'zebra'}})

        code, message = _error(lambda: _scan_begins_with({'N': '1'}))
        assert code == "ValidationException", (
            f"begins_with with an N operand on the {stage} table answered {code!r}, expected "
            f"ValidationException"
        )
        assert message == _INVALID_OPERAND_MESSAGE.format(op_type="N"), (
            f"begins_with with an N operand on the {stage} table said {message!r}, expected "
            f"{_INVALID_OPERAND_MESSAGE.format(op_type='N')!r}"
        )

        code, message = _error(lambda: _scan_begins_with({'BOOL': True}))
        assert code == "ValidationException", (
            f"begins_with with a BOOL operand on the {stage} table answered {code!r}, expected "
            f"ValidationException"
        )
        assert message == _INVALID_OPERAND_MESSAGE.format(op_type="BOOL"), (
            f"begins_with with a BOOL operand on the {stage} table said {message!r}, expected "
            f"{_INVALID_OPERAND_MESSAGE.format(op_type='BOOL')!r}"
        )

        unfiltered = ddb.scan(TableName=t, ConsistentRead=True)
        expected_count = 0 if stage == 'empty' else 2
        assert unfiltered['Count'] == expected_count, (
            f"after the rejected begins_with scans the {stage} table held "
            f"{unfiltered['Count']} item(s), expected {expected_count}: the rejected reads must "
            f"not have written or removed anything"
        )

    # Positive control: begins_with over the correctly-typed S operand still filters normally.
    matched = ddb.scan(
        TableName=t,
        FilterExpression='begins_with(attr, :p)',
        ExpressionAttributeValues={':p': {'S': 'alpha'}},
        ConsistentRead=True,
    )
    matched_pks = {item['pk']['S'] for item in matched['Items']}
    assert matched_pks == {'alpha-item'}, (
        f"begins_with(attr, 'alpha') with a correctly-typed S operand matched {matched_pks!r}, "
        f"expected {{'alpha-item'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
