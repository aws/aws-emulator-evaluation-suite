"""query-capacity-gsi-rejects-consistent-read-lsi-accepts-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-capacity-gsi-rejects-consistent-read-lsi-accepts-it"
GROUP = 'capacity'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
_GSI = 'gsi1'
_LSI = 'lsi1'


def _code(fn):
    """The error code and message *fn* raises; an unexpected success fails loudly instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConsistentRead=True on an ALL-projection GSI Query is refused, the boundary that is why a
    GSI's ReturnConsumedCapacity is only ever measured at eventual consistency, while the
    identical flag on the sibling ALL-projection LSI is accepted.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ccgsilsi-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[{
            'IndexName': _GSI,
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': _LSI,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    ddb.put_item(TableName=table, Item={
        'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'gpk': {'S': 'G'}, 'lsk': {'S': 'L'},
    })

    # --- break exactly one thing: ConsistentRead=True against the GSI ---
    code, message = _code(lambda: ddb.query(
        TableName=table, IndexName=_GSI, ConsistentRead=True,
        KeyConditionExpression='gpk = :g', ExpressionAttributeValues={':g': {'S': 'G'}},
    ))
    assert code == ERR_VALIDATION, (
        f'a strongly consistent Query against a GSI must be refused with {ERR_VALIDATION}; got {code}'
    )
    assert message == 'Consistent reads are not supported on global secondary indexes', (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # --- positive control: the identical flag against the sibling LSI is accepted ---
    lsi_strong = ddb.query(
        TableName=table, IndexName=_LSI, ConsistentRead=True,
        KeyConditionExpression='pk = :p', ExpressionAttributeValues={':p': {'S': 'P'}},
    )
    assert lsi_strong['Items'] == [{'pk': {'S': 'P'}, 'sk': {'S': 'S'}, 'gpk': {'S': 'G'}, 'lsk': {'S': 'L'}}], (
        f'ConsistentRead=True against the ALL-projection LSI must succeed and return the item '
        f'written just before it, got {lsi_strong["Items"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
