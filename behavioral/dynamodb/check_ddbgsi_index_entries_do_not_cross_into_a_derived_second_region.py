"""ddbgsi-index-entries-do-not-cross-into-a-derived-second-region."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbgsi-index-entries-do-not-cross-into-a-derived-second-region"
GROUP = 'gsi'
SERVICES = ['dynamodb']

ERR_VALIDATION = 'ValidationException'
_INDEX = 'gsi1'
_CONVERGE_S = 180


def _second_region(ctx) -> str:
    """Return us-east-1, or us-west-2 when ctx.region is us-east-1 (both enabled by default)."""
    return 'us-east-1' if ctx.region != 'us-east-1' else 'us-west-2'


def _delete_table(client, name: str) -> None:
    """Delete *name*, retrying ResourceInUseException while the table is still CREATING."""
    give_up = time.time() + 300
    while True:
        try:
            client.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.time() >= give_up:
                raise
            time.sleep(5)


def _create(client, name: str) -> None:
    client.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )


def _await_index(client, name: str) -> None:
    client.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    give_up = time.time() + _CONVERGE_S
    status = None
    while time.time() < give_up:
        described = client.describe_table(TableName=name)['Table']
        status = {i['IndexName']: i['IndexStatus']
                  for i in described.get('GlobalSecondaryIndexes', [])}
        if status.get(_INDEX) == 'ACTIVE':
            return
        time.sleep(2)
    raise AssertionError(
        f'{_INDEX} on {name!r} in {client.meta.region_name!r} never became ACTIVE within '
        f'{_CONVERGE_S}s: {status!r}'
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A table and its GSI are regional: same-named tables in two regions share no items or entries.

    Each region's index serves its own item; a consistent GSI query is refused there too.
    """
    home = ctx.client('dynamodb')
    other_region = _second_region(ctx)
    away = ctx.client('dynamodb', region=other_region)
    table = ctx.unique_name('sim2real-behav-ddbgsi-region-')

    # One cleanup per create, registered immediately so neither region's table can leak.
    _create(home, table)
    ctx.on_cleanup(lambda: _delete_table(home, table))
    _create(away, table)
    ctx.on_cleanup(lambda: _delete_table(away, table))

    _await_index(home, table)
    _await_index(away, table)

    home_item = {'pk': {'S': 'ITEM#HOME'}, 'gsi1pk': {'S': 'BUCKET#HOME'},
                 'body': {'S': 'home-payload'}}
    away_item = {'pk': {'S': 'ITEM#AWAY'}, 'gsi1pk': {'S': 'BUCKET#AWAY'},
                 'body': {'S': 'away-payload'}}
    home.put_item(TableName=table, Item=home_item)
    away.put_item(TableName=table, Item=away_item)

    def index_query(client, bucket):
        return client.query(TableName=table, IndexName=_INDEX,
                            KeyConditionExpression='gsi1pk = :g',
                            ExpressionAttributeValues={':g': {'S': bucket}})

    def converge(client, bucket, want_pk):
        items = []
        give_up = time.time() + _CONVERGE_S
        while time.time() < give_up:
            resp = index_query(client, bucket)
            items = resp['Items']
            if [i['pk']['S'] for i in items] == [want_pk]:
                return resp
            time.sleep(1)
        raise AssertionError(
            f'the index in {client.meta.region_name!r} never converged on {want_pk!r} under '
            f'{bucket!r} within {_CONVERGE_S}s; the last read held {items!r}'
        )

    # Each region's own index works -- the positive control for both absences below.
    home_seen = converge(home, 'BUCKET#HOME', 'ITEM#HOME')
    away_seen = converge(away, 'BUCKET#AWAY', 'ITEM#AWAY')
    assert home_seen['Items'][0]['body']['S'] == 'home-payload', (
        f'{ctx.region} returned the wrong item for its own index key: {home_seen["Items"]!r}'
    )
    assert away_seen['Items'][0]['body']['S'] == 'away-payload', (
        f'{other_region} returned the wrong item for its own index key: {away_seen["Items"]!r}'
    )

    # Effect absent, in both directions: neither region's index or base table holds the other's
    # item, even though both tables carry the same name and the same index.
    home_foreign = index_query(home, 'BUCKET#AWAY')
    assert home_foreign['Items'] == [], (
        f'{ctx.region}\'s index returned an item written in {other_region}: '
        f'{home_foreign["Items"]!r}'
    )
    away_foreign = index_query(away, 'BUCKET#HOME')
    assert away_foreign['Items'] == [], (
        f'{other_region}\'s index returned an item written in {ctx.region}: '
        f'{away_foreign["Items"]!r}'
    )
    home_base = home.get_item(TableName=table, Key={'pk': away_item['pk']}, ConsistentRead=True)
    assert 'Item' not in home_base, (
        f'{ctx.region}\'s base table holds the item written in {other_region}: '
        f'{home_base.get("Item")!r}'
    )
    away_base = away.get_item(TableName=table, Key={'pk': home_item['pk']}, ConsistentRead=True)
    assert 'Item' not in away_base, (
        f'{other_region}\'s base table holds the item written in {ctx.region}: '
        f'{away_base.get("Item")!r}'
    )

    # The base table in the partner region is strongly consistent, and its GSI still refuses to be.
    away_own = away.get_item(TableName=table, Key={'pk': away_item['pk']}, ConsistentRead=True)
    assert away_own['Item']['body']['S'] == 'away-payload', (
        f'the strongly consistent base read in {other_region} did not see its own write: '
        f'{away_own.get("Item")!r}'
    )
    try:
        accepted = away.query(TableName=table, IndexName=_INDEX, ConsistentRead=True,
                              KeyConditionExpression='gsi1pk = :g',
                              ExpressionAttributeValues={':g': {'S': 'BUCKET#AWAY'}})
    except ClientError as exc:
        refused = exc.response
        accepted = None
    else:
        refused = None
    assert accepted is None, (
        f'ConsistentRead=True on a GSI must be refused in {other_region} as well, but it was '
        f'accepted and returned {accepted.get("Items")!r}'
    )
    assert refused['Error']['Code'] == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for a consistent GSI read in {other_region}, got '
        f'{refused["Error"]["Code"]!r} ({refused["Error"].get("Message")!r})'
    )
    assert refused['Error']['Message'] == "Consistent reads are not supported on global secondary indexes", (
        f"expected AWS's exact ValidationException message, got {refused['Error']['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
