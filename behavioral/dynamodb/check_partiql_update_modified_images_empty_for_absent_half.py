"""partiql-update-modified-images-empty-for-absent-half."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-update-modified-images-empty-for-absent-half"
GROUP = 'partiql'
SERVICES = ['dynamodb']


def _stored(ddb, table):
    return ddb.get_item(
        TableName=table, Key={'pk': {'S': 'p1'}, 'sk': {'S': 's1'}}, ConsistentRead=True,
    ).get('Item')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATE ... RETURNING MODIFIED NEW * after a REMOVE carries no items, because a removed
    attribute has no new value; RETURNING MODIFIED OLD * after SET on an attribute that did not
    exist carries no items, because it has no old value. Each has a present-value counterpart.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlmod-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    key = {'pk': {'S': 'p1'}, 'sk': {'S': 's1'}}
    original = {**key, 'name': {'S': 'Ada'}, 'qty': {'N': '3'}}
    ddb.put_item(TableName=table, Item=original)
    where = "WHERE pk = 'p1' AND sk = 's1'"

    # 1. REMOVE qty, RETURNING MODIFIED NEW *: the removed attribute has no new value, so the
    # statement carries no items even though it changed the item.
    r1 = ddb.execute_statement(Statement=f'UPDATE "{table}" REMOVE qty {where} RETURNING MODIFIED NEW *')
    assert r1['Items'] == [], (
        f'RETURNING MODIFIED NEW * after REMOVE qty must carry no items, got {r1["Items"]!r}'
    )
    after1 = {k: v for k, v in original.items() if k != 'qty'}
    assert _stored(ddb, table) == after1, (
        f'after REMOVE qty the stored item must be {after1!r}, got {_stored(ddb, table)!r}'
    )

    # 2. SET qty back (now a brand-new attribute, since it was just removed), RETURNING
    # MODIFIED OLD *: a brand-new attribute has no old value, so the statement carries no items.
    r2 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET qty = 5 {where} RETURNING MODIFIED OLD *')
    assert r2['Items'] == [], (
        f'RETURNING MODIFIED OLD * after SET on a brand-new attribute must carry no items, '
        f'got {r2["Items"]!r}'
    )
    after2 = {**after1, 'qty': {'N': '5'}}
    assert _stored(ddb, table) == after2, (
        f'after SET qty = 5 the stored item must be {after2!r}, got {_stored(ddb, table)!r}'
    )

    # 3. Positive control: SET on the now-existing qty, RETURNING MODIFIED OLD * carries the
    # one attribute's prior value.
    r3 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET qty = 9 {where} RETURNING MODIFIED OLD *')
    want3 = [{'qty': {'N': '5'}}]
    assert r3['Items'] == want3, (
        f'RETURNING MODIFIED OLD * on an attribute that already existed must carry its prior '
        f'value {want3!r}, got {r3["Items"]!r}'
    )
    after3 = {**after2, 'qty': {'N': '9'}}
    assert _stored(ddb, table) == after3, (
        f'after SET qty = 9 the stored item must be {after3!r}, got {_stored(ddb, table)!r}'
    )

    # 4. Positive control: SET on a brand-new attribute, RETURNING MODIFIED NEW * carries that
    # attribute's new value even though it did not exist before.
    r4 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET status = \'active\' {where} RETURNING MODIFIED NEW *')
    want4 = [{'status': {'S': 'active'}}]
    assert r4['Items'] == want4, (
        f'RETURNING MODIFIED NEW * on SET of a brand-new attribute must carry its new value '
        f'{want4!r}, got {r4["Items"]!r}'
    )
    after4 = {**after3, 'status': {'S': 'active'}}
    assert _stored(ddb, table) == after4, (
        f'after SET status = active the stored item must be {after4!r}, got {_stored(ddb, table)!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
