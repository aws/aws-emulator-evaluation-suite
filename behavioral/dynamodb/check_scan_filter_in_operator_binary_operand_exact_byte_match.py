"""scan-filter-in-operator-binary-operand-exact-byte-match."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'scan-filter-in-operator-binary-operand-exact-byte-match'
GROUP = 'expressions'
SERVICES = ['dynamodb']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _seed_blob_table(ctx) -> str:
    """Table seeded with Binary-typed blob attributes sharing byte prefixes."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    rows = [
        ('u1', b'\x00\x01\x02'),
        ('u2', b'\x00\x01\x03'),
        ('u3', b'\x00\x01\x02\x00'),
        ('u4', b'\xff\xfe'),
    ]
    for pk, blob in rows:
        ddb.put_item(TableName=t, Item={'pk': {'S': pk}, 'blob': {'B': blob}})
    return t


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterExpression 'IN (...)' on a Binary operand matches by exact byte sequence,
    not by a shared byte prefix or a trailing null byte.
    """
    ddb = ctx.client('dynamodb')
    t = _seed_blob_table(ctx)

    resp = ddb.scan(
        TableName=t,
        FilterExpression='#b IN (:v1, :v2)',
        ExpressionAttributeNames={'#b': 'blob'},
        ExpressionAttributeValues={
            ':v1': {'B': b'\x00\x01\x02'},
            ':v2': {'B': b'\xff\xfe'},
        },
        ConsistentRead=True,
    )
    pks = {item['pk']['S'] for item in resp['Items']}
    assert resp['Count'] == 2, f"expected Count=2 for blob IN (00 01 02, ff fe), got {resp['Count']}"
    assert pks == {'u1', 'u4'}, f"expected pks {{'u1', 'u4'}} for blob IN (00 01 02, ff fe), got {pks}"

    resp_padded = ddb.scan(
        TableName=t,
        FilterExpression='#b IN (:v3)',
        ExpressionAttributeNames={'#b': 'blob'},
        ExpressionAttributeValues={':v3': {'B': b'\x00\x01\x02\x00'}},
        ConsistentRead=True,
    )
    padded_pks = {item['pk']['S'] for item in resp_padded['Items']}
    assert resp_padded['Count'] == 1, (
        f"expected Count=1 for blob IN (00 01 02 00), got {resp_padded['Count']}"
    )
    assert padded_pks == {'u3'}, (
        f"expected the trailing-null-extended value to match only u3, got {padded_pks}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
