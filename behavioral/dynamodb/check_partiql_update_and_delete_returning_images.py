"""partiql-update-and-delete-returning-images."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-update-and-delete-returning-images"
GROUP = 'partiql'
SERVICES = ['dynamodb']


def _stored(ddb, table, key):
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATE RETURNING ALL OLD *, MODIFIED NEW * and ALL NEW *, and DELETE RETURNING ALL OLD *, each
    return the documented image of the item, and a consistent read matches the state each write left.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.delete.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlret-')
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
    original = {**key, 'name': {'S': 'Ada'}, 'qty': {'N': '3'}, 'tags': {'L': [{'S': 'x'}, {'N': '7'}]}}
    ddb.put_item(TableName=table, Item=original)
    where = "WHERE pk = 'p1' AND sk = 's1'"

    # 1. ALL OLD *: the whole item as it was before the write, without the attribute it adds.
    r1 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET qty = 4 SET note = \'n1\' {where} RETURNING ALL OLD *')
    assert r1['Items'] == [original], (
        f'RETURNING ALL OLD * must return the complete pre-update item and nothing else.\n'
        f'want: {[original]!r}\ngot:  {r1["Items"]!r}'
    )
    after1 = {**original, 'qty': {'N': '4'}, 'note': {'S': 'n1'}}
    assert _stored(ddb, table, key) == after1, (
        f'after SET qty = 4 SET note = n1 the stored item must be {after1!r}, got '
        f'{_stored(ddb, table, key)!r}'
    )

    # 2. MODIFIED NEW *: only the attributes this statement set, at their new values.
    r2 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET qty = 5 SET name = \'Bea\' {where} RETURNING MODIFIED NEW *')
    want2 = [{'qty': {'N': '5'}, 'name': {'S': 'Bea'}}]
    assert r2['Items'] == want2, (
        f'RETURNING MODIFIED NEW * must return exactly the two set attributes at their new values '
        f'(no key, no untouched attribute).\nwant: {want2!r}\ngot:  {r2["Items"]!r}'
    )
    after2 = {**after1, 'qty': {'N': '5'}, 'name': {'S': 'Bea'}}
    assert _stored(ddb, table, key) == after2, (
        f'after SET qty = 5 SET name = Bea the stored item must be {after2!r}, got '
        f'{_stored(ddb, table, key)!r}'
    )

    # 3. ALL NEW *: the whole post-update item, which no longer holds the removed attribute.
    r3 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" REMOVE note {where} RETURNING ALL NEW *')
    after3 = {k: v for k, v in after2.items() if k != 'note'}
    assert r3['Items'] == [after3], (
        f'RETURNING ALL NEW * after REMOVE note must return the complete post-update item.\n'
        f'want: {[after3]!r}\ngot:  {r3["Items"]!r}'
    )
    assert _stored(ddb, table, key) == after3, (
        f'after REMOVE note the stored item must be {after3!r}, got {_stored(ddb, table, key)!r}'
    )

    # 4. DELETE ... RETURNING ALL OLD *: the removed item, whole; then the key reads absent.
    r4 = ddb.execute_statement(Statement=f'DELETE FROM "{table}" {where} RETURNING ALL OLD *')
    assert r4['Items'] == [after3], (
        f'DELETE ... RETURNING ALL OLD * must return the complete item it removed.\n'
        f'want: {[after3]!r}\ngot:  {r4["Items"]!r}'
    )
    gone = _stored(ddb, table, key)
    assert gone is None, f'the deleted item must be absent from a consistent GetItem, got {gone!r}'

    # 5. A second DELETE of the same key succeeds and returns no image: there was nothing to delete.
    r5 = ddb.execute_statement(Statement=f'DELETE FROM "{table}" {where} RETURNING ALL OLD *')
    assert r5['Items'] == [], (
        f'DELETE of an absent key with RETURNING ALL OLD * returns no items, got {r5["Items"]!r}'
    )

    # 6-9: MODIFIED NEW/OLD narrow to the exact nested leaf touched, not the whole top-level
    # attribute, when the SET target is a nested map path or a list index.
    key2 = {'pk': {'S': 'p2'}, 'sk': {'S': 's2'}}
    where2 = "WHERE pk = 'p2' AND sk = 's2'"
    nested_original = {
        **key2,
        'meta': {'M': {'nested': {'S': 'v0'}, 'other': {'N': '1'}}},
        'tags': {'L': [{'S': 'a'}, {'S': 'b'}, {'S': 'c'}]},
    }
    ddb.put_item(TableName=table, Item=nested_original)

    # 6. MODIFIED OLD * over a nested map path: only the touched leaf, not the sibling attribute.
    r6 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET meta.nested = \'v1\' {where2} RETURNING MODIFIED OLD *')
    want6 = [{'meta': {'M': {'nested': {'S': 'v0'}}}}]
    assert r6['Items'] == want6, (
        f'RETURNING MODIFIED OLD * over a nested map path must return only the pre-update leaf, '
        f'nested under its top-level attribute, with no sibling.\nwant: {want6!r}\ngot:  {r6["Items"]!r}'
    )

    # 7. MODIFIED NEW * over the same nested map path: only the touched leaf at its new value.
    r7 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET meta.nested = \'v2\' {where2} RETURNING MODIFIED NEW *')
    want7 = [{'meta': {'M': {'nested': {'S': 'v2'}}}}]
    assert r7['Items'] == want7, (
        f'RETURNING MODIFIED NEW * over a nested map path must return only the post-update leaf, '
        f'nested under its top-level attribute, with no sibling.\nwant: {want7!r}\ngot:  {r7["Items"]!r}'
    )

    # 8. MODIFIED OLD * over a list index: only the touched element, not the sibling elements.
    r8 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[0] = \'z\' {where2} RETURNING MODIFIED OLD *')
    want8 = [{'tags': {'L': [{'S': 'a'}]}}]
    assert r8['Items'] == want8, (
        f'RETURNING MODIFIED OLD * over a list index must return only the pre-update element, as '
        f'a single-element list under its top-level attribute.\nwant: {want8!r}\ngot:  {r8["Items"]!r}'
    )

    # 9. MODIFIED NEW * over the same list index: only the touched element at its new value.
    r9 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[0] = \'y\' {where2} RETURNING MODIFIED NEW *')
    want9 = [{'tags': {'L': [{'S': 'y'}]}}]
    assert r9['Items'] == want9, (
        f'RETURNING MODIFIED NEW * over a list index must return only the post-update element, as '
        f'a single-element list under its top-level attribute.\nwant: {want9!r}\ngot:  {r9["Items"]!r}'
    )
    stored2 = _stored(ddb, table, key2)
    want_stored2 = {
        **key2,
        'meta': {'M': {'nested': {'S': 'v2'}, 'other': {'N': '1'}}},
        'tags': {'L': [{'S': 'y'}, {'S': 'b'}, {'S': 'c'}]},
    }
    assert stored2 == want_stored2, (
        f'after the nested-path and list-index SETs the stored item must be {want_stored2!r}, got '
        f'{stored2!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
