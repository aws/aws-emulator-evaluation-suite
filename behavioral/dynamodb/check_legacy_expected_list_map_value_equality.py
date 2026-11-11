"""legacy-expected-list-map-value-equality."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-list-map-value-equality"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'
ERR_CCFE_MESSAGE = 'The conditional request failed'

LIST_VALUE = {'L': [{'S': 'x'}, {'N': '1'}]}
LIST_OTHER = {'L': [{'S': 'x'}, {'N': '2'}]}
MAP_VALUE = {'M': {'a': {'S': 'y'}, 'b': {'N': '1'}}}
MAP_OTHER = {'M': {'a': {'S': 'y'}, 'b': {'N': '2'}}}

# For each document kind: the condition's reference value, and a stored value that differs from
# it only in one nested element.
DOC_KINDS = (
    ('list', LIST_VALUE, LIST_OTHER),
    ('map', MAP_VALUE, MAP_OTHER),
)
# For each legacy Expected form: how to build the condition dict for a given reference value.
FORMS = (
    ('value', lambda ref: {'Value': ref}),
    ('comparator', lambda ref: {'ComparisonOperator': 'EQ', 'AttributeValueList': [ref]}),
)
STATES = ('match', 'mismatch')


def _apply(ddb, table, pk, ref_value, condition):
    """Run one Expected-guarded PutItem that rewrites doc to ref_value and sets marker;
    return ('ok', None, None) or ('error', code, msg)."""
    try:
        ddb.put_item(
            TableName=table,
            Item={'pk': {'S': pk}, 'doc': ref_value, 'marker': {'S': 'applied'}},
            Expected={'doc': condition},
        )
    except ClientError as exc:
        err = exc.response['Error']
        return 'error', err['Code'], err['Message']
    return 'ok', None, None


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Legacy Expected equality (Value, and ComparisonOperator EQ) on a List or Map
    AttributeValue is graded by deep structural equality on PutItem.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-expdoc-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    for kind_name, ref_value, other_value in DOC_KINDS:
        for form_name, build_condition in FORMS:
            for state in STATES:
                pk = f'{kind_name}-{form_name}-{state}'
                stored = ref_value if state == 'match' else other_value
                ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'doc': stored})
                label = f'{kind_name}/{form_name}/{state}'

                kind, code, message = _apply(ddb, table, pk, ref_value, build_condition(ref_value))

                if state == 'match':
                    assert kind == 'ok', (
                        f'{label}: expected the deep-equal {kind_name} to satisfy the legacy '
                        f'Expected condition, got {code}: {message!r}'
                    )
                else:
                    assert kind == 'error', (
                        f'{label}: expected {ERR_CONDITIONAL_CHECK_FAILED} for a {kind_name} '
                        f'that differs by a nested element, call succeeded'
                    )
                    assert code == ERR_CONDITIONAL_CHECK_FAILED, (
                        f'{label}: expected {ERR_CONDITIONAL_CHECK_FAILED}, got {code}: {message!r}'
                    )
                    assert message == ERR_CCFE_MESSAGE, f'{label}: unexpected message {message!r}'

                got = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')
                if state == 'match':
                    assert got is not None and got.get('doc') == ref_value and got.get('marker') == {'S': 'applied'}, (
                        f'{label}: a successful conditional PutItem did not land: {got!r}'
                    )
                else:
                    assert got is not None and got.get('doc') == other_value and 'marker' not in got, (
                        f'{label}: a rejected conditional PutItem must leave doc unchanged: {got!r}'
                    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
