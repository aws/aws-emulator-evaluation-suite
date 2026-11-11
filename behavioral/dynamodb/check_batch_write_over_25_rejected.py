"""batch-write-over-25-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-over-25-rejected"
GROUP = 'batch'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem with >25 items raises ValidationException and writes nothing,
    while a request at the 25-item limit on the same table succeeds."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    control_requests = [{'PutRequest': {'Item': {'pk': {'S': f'bw-ctrl-{i:03d}'}}}} for i in range(25)]
    control_resp = ddb.batch_write_item(RequestItems={table: control_requests})
    assert not control_resp.get('UnprocessedItems'), (
        f'expected 25-item control batch fully accepted, got unprocessed: {control_resp.get("UnprocessedItems")!r}'
    )
    got_control = ddb.get_item(TableName=table, Key={'pk': {'S': 'bw-ctrl-000'}}, ConsistentRead=True).get('Item')
    assert got_control is not None, 'expected control item bw-ctrl-000 to be written'

    requests = [{'PutRequest': {'Item': {'pk': {'S': f'bw-over-{i:03d}'}}}} for i in range(26)]
    try:
        ddb.batch_write_item(RequestItems={table: requests})
        code = message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    expected = _over_limit_message(table, [f'bw-over-{i:03d}' for i in range(26)])
    assert message == expected, f'expected message {expected!r}, got {message!r}'

    got_over = ddb.get_item(TableName=table, Key={'pk': {'S': 'bw-over-000'}}, ConsistentRead=True).get('Item')
    assert got_over is None, f'expected rejected batch to write nothing, found item: {got_over!r}'


_NULL_MEMBERS = ', '.join(
    f'{m}=null' for m in ('n', 'b', 'iNT', 'dECIMAL', 'dOUBLE', 'sS', 'nS', 'bS', 'iNTSET', 'dECIMALSET',
                          'dOUBLESET', 'm', 'l', 'nULL', 'bOOL')
)


def _over_limit_message(table, keys):
    """The ValidationException message AWS returns for an over-limit batch of string-key puts:
    it renders every request of the batch, in order."""
    writes = ', '.join(
        f'WriteRequest(putRequest=PutRequest(item={{pk=AttributeValue(s={k}, {_NULL_MEMBERS})}}, '
        'workloadProfileName=null), deleteRequest=null)'
        for k in keys
    )
    return (
        f"1 validation error detected: Value '{{{table}=[{writes}]}}' at 'requestItems' failed to satisfy "
        "constraint: Map value must satisfy constraint: [Member must have length less than or equal to 25, "
        "Member must have length greater than or equal to 1]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
