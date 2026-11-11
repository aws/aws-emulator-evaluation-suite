"""batch-execute-statement-consistent-read-is-billed-per-member."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-consistent-read-is-billed-per-member"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement bills each statement's own ConsistentRead: an eventual
    1-item SELECT costs half a consistent one, an explicit false equals omitting the
    member, and a batch mixing both sums each statement's own cost."""
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
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.execute_statement(Statement=f'''INSERT INTO "{t}" VALUE {{'pk':'a'}}''')
    ddb.execute_statement(Statement=f'''INSERT INTO "{t}" VALUE {{'pk':'b'}}''')

    def _select(pk: str, consistent_read: bool | None) -> dict:
        stmt = {'Statement': f'''SELECT * FROM "{t}" WHERE pk='{pk}' '''.strip()}
        if consistent_read is not None:
            stmt['ConsistentRead'] = consistent_read
        return ddb.batch_execute_statement(Statements=[stmt], ReturnConsumedCapacity='TOTAL')

    omitted = _select('a', None)
    omitted_cc = omitted['ConsumedCapacity']
    assert isinstance(omitted_cc, list) and len(omitted_cc) == 1, (
        f'expected one per-table ConsumedCapacity entry, got {omitted_cc!r}'
    )
    omitted_cu = omitted_cc[0]['CapacityUnits']
    assert omitted_cu == 0.5, f'an eventual 1-item SELECT must bill 0.5, got {omitted_cu!r}'

    eventual = _select('a', False)['ConsumedCapacity'][0]['CapacityUnits']
    assert eventual == 0.5, f'ConsistentRead=False must bill 0.5, got {eventual!r}'
    assert eventual == omitted_cu, (
        f'ConsistentRead=False must equal omitting the member, got {eventual!r} vs {omitted_cu!r}'
    )

    consistent = _select('a', True)['ConsumedCapacity'][0]['CapacityUnits']
    assert consistent == 1.0, f'ConsistentRead=True must bill 1.0, got {consistent!r}'
    assert consistent == omitted_cu * 2, (
        f'a consistent read must cost exactly twice an eventual one, got {consistent!r} vs {omitted_cu!r}'
    )

    mixed = ddb.batch_execute_statement(
        Statements=[
            {'Statement': f'''SELECT * FROM "{t}" WHERE pk='a' ''', 'ConsistentRead': True},
            {'Statement': f'''SELECT * FROM "{t}" WHERE pk='b' ''', 'ConsistentRead': False},
        ],
        ReturnConsumedCapacity='TOTAL',
    )
    mixed_responses = mixed['Responses']
    assert len(mixed_responses) == 2, f'expected 2 per-statement responses, got {len(mixed_responses)}'
    assert mixed_responses[0]['Item'] == {'pk': {'S': 'a'}}, (
        f"expected responses[0] to carry item a, got {mixed_responses[0]}"
    )
    assert mixed_responses[1]['Item'] == {'pk': {'S': 'b'}}, (
        f"expected responses[1] to carry item b, got {mixed_responses[1]}"
    )
    mixed_cc = mixed['ConsumedCapacity']
    assert isinstance(mixed_cc, list) and len(mixed_cc) == 1, (
        f'both statements read the same table, expected one entry, got {mixed_cc!r}'
    )
    mixed_cu = mixed_cc[0]['CapacityUnits']
    assert mixed_cu == 1.5, (
        f'a consistent member plus an eventual member must sum to 1.5, got {mixed_cu!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
