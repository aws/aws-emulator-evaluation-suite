"""execute-statement-gsi-consistent-read-rejected-while-lsi-consistent-read-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-gsi-consistent-read-rejected-while-lsi-consistent-read-succeeds"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT with ConsistentRead=True reads its own write through an LSI but is
    rejected with ValidationException and no data on a GSI that is live for eventual reads.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlconsist-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'status', 'AttributeType': 'S'},
            {'AttributeName': 'createdAt', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'status-index',
            'KeySchema': [{'AttributeName': 'status', 'KeyType': 'HASH'}, {'AttributeName': 'createdAt', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'alternate-index',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.time() + 300
    gsi_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        gsi_status = {i['IndexName']: i['IndexStatus'] for i in described.get('GlobalSecondaryIndexes', [])}
        if gsi_status.get('status-index') == 'ACTIVE':
            break
        time.sleep(2)
    assert gsi_status.get('status-index') == 'ACTIVE', f'status-index never became ACTIVE: {gsi_status!r}'

    pk = 'P1'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'sk': {'S': 'S1'}, 'status': {'S': 'active'}, 'createdAt': {'S': '2024-01-01'}})

    # Positive control 1: the LSI shares the base table's partition and is strongly consistent,
    # so a ConsistentRead=True SELECT through it must see the write it immediately followed.
    lsi_resp = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}"."alternate-index" WHERE pk = \'{pk}\'',
        ConsistentRead=True,
    )
    lsi_items = lsi_resp.get('Items', [])
    assert [i['pk']['S'] for i in lsi_items] == [pk], (
        f'the strongly consistent LSI SELECT did not see the write it followed: {lsi_items!r}'
    )

    # The same ConsistentRead=True flag, against the global index.
    try:
        accepted = ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."status-index" WHERE status = \'active\'',
            ConsistentRead=True,
        )
    except ClientError as exc:
        rejected = exc.response
        accepted = None
    else:
        rejected = None

    assert accepted is None, (
        f'ConsistentRead=True on a global secondary index via ExecuteStatement must be rejected, '
        f'but the service accepted it and returned {accepted.get("Items") if accepted else None!r}'
    )
    code = rejected['Error'].get('Code')
    assert code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for ConsistentRead on a GSI via ExecuteStatement, got '
        f'{code!r} ({rejected["Error"].get("Message")!r})'
    )
    expected = 'Strongly consistent read is not supported on Global Secondary Indexes'
    message = rejected['Error'].get('Message')
    assert message == expected, f'expected message {expected!r}, got {message!r}'
    # The rejection carries no Items key at all, not an empty page.
    assert 'Items' not in rejected, (
        f'the rejected consistent-read statement still returned data: {rejected.get("Items")!r}'
    )

    # Positive control 2: the GSI is live for an eventually consistent read, so the rejection is
    # about the flag; polled because GSI propagation is eventually consistent.
    deadline = time.time() + 120
    gsi_items = []
    while time.time() < deadline:
        gsi_items = ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."status-index" WHERE status = \'active\'',
        ).get('Items', [])
        if gsi_items:
            break
        time.sleep(1)
    assert [i['pk']['S'] for i in gsi_items] == [pk], (
        f'the GSI never became queryable through ExecuteStatement within 120s, so the rejection '
        f'above would not be about consistency: {gsi_items!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
