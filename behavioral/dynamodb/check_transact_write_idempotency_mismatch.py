"""transact-write-idempotency-mismatch."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-idempotency-mismatch"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_IDEMPOTENT_MISMATCH = 'IdempotentParameterMismatchException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a TransactWriteItems ClientRequestToken with a different item fails with
    IdempotentParameterMismatchException and writes nothing; reuse with the same item is a no-op."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    token = str(uuid.uuid4())
    original_write = {'Put': {'TableName': table, 'Item': {'pk': {'S': 'idem-m1'}, 'v': {'N': '1'}}}}

    # Positive control: the first write with a fresh token succeeds and lands.
    ddb.transact_write_items(TransactItems=[original_write], ClientRequestToken=token)
    original = ddb.get_item(TableName=table, Key={'pk': {'S': 'idem-m1'}}, ConsistentRead=True).get('Item')
    assert original == {'pk': {'S': 'idem-m1'}, 'v': {'N': '1'}}, f'positive control: first write must land, got {original}'

    try:
        ddb.transact_write_items(TransactItems=[{'Put': {'TableName': table, 'Item': {'pk': {'S': 'idem-m2'}, 'v': {'N': '2'}}}}], ClientRequestToken=token)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_IDEMPOTENT_MISMATCH, f'expected {ERR_IDEMPOTENT_MISMATCH}, got {code!r}'
    assert message == "Specified idempotent token was used with different request parameters within the idempotency window", (
        f"expected AWS's exact IdempotentParameterMismatchException message, got {message!r}"
    )

    unwritten = ddb.get_item(TableName=table, Key={'pk': {'S': 'idem-m2'}}, ConsistentRead=True).get('Item')
    assert unwritten is None, f'rejected mismatched write must not apply, got {unwritten}'
    still = ddb.get_item(TableName=table, Key={'pk': {'S': 'idem-m1'}}, ConsistentRead=True).get('Item')
    assert still == {'pk': {'S': 'idem-m1'}, 'v': {'N': '1'}}, f'original item must remain unchanged, got {still}'

    # Positive control: shows the rejection is about the mismatch, not any token reuse.
    ddb.transact_write_items(TransactItems=[original_write], ClientRequestToken=token)
    replayed = ddb.get_item(TableName=table, Key={'pk': {'S': 'idem-m1'}}, ConsistentRead=True).get('Item')
    assert replayed == {'pk': {'S': 'idem-m1'}, 'v': {'N': '1'}}, f'identical replay of the same token must not raise or change state, got {replayed}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
