"""update-item-return-values-distinguishes-all-five-arms."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-return-values-distinguishes-all-five-arms"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """The five ReturnValues arms are five different answers, and each pins the others: NONE returns
    nothing, ALL_OLD/ALL_NEW the whole item before/after, UPDATED_OLD/UPDATED_NEW ONLY the
    attribute that changed. An engine collapsing any pair fails here."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    def _reset():
        ddb.put_item(TableName=table, Item={'pk': {'S': 'rv'}, 'v': {'N': '1'}, 'w': {'N': '1'}})

    got = {}
    for arm in ('NONE', 'ALL_OLD', 'UPDATED_OLD', 'ALL_NEW', 'UPDATED_NEW'):
        _reset()
        res = ddb.update_item(TableName=table, Key={'pk': {'S': 'rv'}}, UpdateExpression='SET v = :v',
                              ExpressionAttributeValues={':v': {'N': '2'}}, ReturnValues=arm)
        got[arm] = res.get('Attributes')
    assert got['NONE'] is None, f"NONE must return no Attributes, got {got['NONE']}"
    assert got['UPDATED_OLD'] == {'v': {'N': '1'}}, (
        f"UPDATED_OLD returns ONLY the changed attribute's old value, got {got['UPDATED_OLD']}"
    )
    assert got['UPDATED_NEW'] == {'v': {'N': '2'}}, (
        f"UPDATED_NEW returns ONLY the changed attribute's new value, got {got['UPDATED_NEW']}"
    )
    assert got['ALL_OLD'] == {'pk': {'S': 'rv'}, 'v': {'N': '1'}, 'w': {'N': '1'}}, (
        f"ALL_OLD returns the whole prior item, got {got['ALL_OLD']}"
    )
    assert got['ALL_NEW'] == {'pk': {'S': 'rv'}, 'v': {'N': '2'}, 'w': {'N': '1'}}, (
        f"ALL_NEW returns the whole updated item, got {got['ALL_NEW']}"
    )
    assert got['UPDATED_NEW'] != got['ALL_NEW'], (
        'UPDATED_NEW and ALL_NEW must differ: the unchanged attribute w belongs only to ALL_NEW'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
