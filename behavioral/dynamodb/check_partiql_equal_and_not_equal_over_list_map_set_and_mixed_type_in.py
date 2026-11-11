"""partiql-equal-and-not-equal-over-list-map-set-and-mixed-type-in."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-equal-and-not-equal-over-list-map-set-and-mixed-type-in"
GROUP = 'partiql'
SERVICES = ['dynamodb']

# pk -> val, one item per non-scalar type plus a sibling of the same type.
_COMPLEX_ITEMS = {
    'list1': {'L': [{'N': '1'}, {'N': '2'}]},
    'list2': {'L': [{'N': '3'}]},
    'map1': {'M': {'x': {'N': '1'}}},
    'map2': {'M': {'x': {'N': '2'}}},
    'set1': {'SS': ['a', 'b']},
    'set2': {'SS': ['c']},
}

# pk -> val, one item per scalar type the mixed-type IN list probes.
_SCALAR_ITEMS = {
    'num_match': {'N': '1'},
    'str_match': {'S': 'a'},
    'bool_match': {'BOOL': True},
    'num_miss': {'N': '99'},
}


def _select(ddb, table, where):
    items = ddb.execute_statement(Statement=f'SELECT * FROM "{table}" WHERE {where}', ConsistentRead=True)['Items']
    return {i['pk']['S'] for i in items}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL = and <> compare List, Map and String Set operands by full value, and IN accepts
    a list mixing Number, String and Boolean literals, matching each by its own type.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqleq-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    for pk, val in {**_COMPLEX_ITEMS, **_SCALAR_ITEMS}.items():
        ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'val': val})

    all_pks = set(_COMPLEX_ITEMS) | set(_SCALAR_ITEMS)

    for pk, literal in (('list1', '[1, 2]'), ('map1', "{'x': 1}"), ('set1', "<<'a', 'b'>>")):
        matched = _select(ddb, table, f'val = {literal}')
        assert matched == {pk}, f"val = {literal} returned {sorted(matched)!r}, expected [{pk!r}]"

        not_matched = _select(ddb, table, f'val <> {literal}')
        assert not_matched == all_pks - {pk}, (
            f"val <> {literal} returned {sorted(not_matched)!r}, expected everything but {pk!r}"
        )

    in_matched = _select(ddb, table, "val IN (1, 'a', true)")
    assert in_matched == {'num_match', 'str_match', 'bool_match'}, (
        f"val IN (1, 'a', true) returned {sorted(in_matched)!r}, expected the number, string and "
        f"boolean matches only, not the mismatched number"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
