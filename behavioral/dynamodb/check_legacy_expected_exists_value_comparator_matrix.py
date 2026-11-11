"""legacy-expected-exists-value-comparator-matrix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-exists-value-comparator-matrix"
GROUP = 'conditions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'
ERR_CCFE_MESSAGE = 'The conditional request failed'

MATCH = {'S': 'match'}
MISMATCH = {'S': 'mismatch'}
NEW = {'S': 'new'}


def _validation(detail: str) -> tuple:
    return ('validation', f'1 validation error detected: One or more parameter values were invalid: {detail}')

# Every legacy Expected shape for one attribute ('attr'): whether 'Exists' is given (and its
# value), whether 'Value' is given, whether the ComparisonOperator form is given, the
# attribute's precondition state, and the outcome AWS gives for that combination.
CASES = [
    ('exists_true_value_match', {'Exists': True, 'Value': MATCH}, 'match', ('ok',)),
    ('exists_true_value_mismatch', {'Exists': True, 'Value': MATCH}, 'mismatch',
     ('ccfe',)),
    ('exists_true_no_value', {'Exists': True}, 'match',
     _validation("Value must be provided when Exists is true for Attribute: attr")),
    ('exists_false_with_value', {'Exists': False, 'Value': MATCH}, 'match',
     _validation("Value cannot be used when Exists is false for Attribute: attr")),
    ('exists_false_bare_absent', {'Exists': False}, 'absent', ('ok',)),
    ('exists_false_bare_present', {'Exists': False}, 'match', ('ccfe',)),
    ('exists_true_plus_comparator',
     {'Exists': True, 'ComparisonOperator': 'EQ', 'AttributeValueList': [MATCH]}, 'match',
     _validation("Exists and ComparisonOperator cannot be used together for Attribute: attr")),
    ('exists_false_plus_comparator',
     {'Exists': False, 'ComparisonOperator': 'EQ', 'AttributeValueList': [MATCH]}, 'match',
     _validation("Exists and ComparisonOperator cannot be used together for Attribute: attr")),
    ('comparator_alone_match', {'ComparisonOperator': 'EQ', 'AttributeValueList': [MATCH]},
     'match', ('ok',)),
    ('comparator_alone_on_missing', {'ComparisonOperator': 'EQ', 'AttributeValueList': [MATCH]},
     'absent', ('ccfe',)),
    ('value_plus_comparator_no_exists',
     {'Value': MATCH, 'ComparisonOperator': 'EQ', 'AttributeValueList': [MATCH]}, 'match',
     _validation("Value and AttributeValueList cannot be used together for Attribute: attr")),
    ('empty_expected_entry', {}, 'match',
     _validation("Value must be provided when Exists is null for Attribute: attr")),
    ('implicit_exists_match', {'Value': MATCH}, 'match', ('ok',)),
    ('implicit_exists_mismatch', {'Value': MATCH}, 'mismatch', ('ccfe',)),
]
OPERATIONS = ('Put', 'Update', 'Delete')


def _setup_item(ddb, table, pk, state):
    item = {'pk': {'S': pk}}
    if state == 'match':
        item['attr'] = MATCH
    elif state == 'mismatch':
        item['attr'] = MISMATCH
    ddb.put_item(TableName=table, Item=item)


def _apply(ddb, table, op, pk, condition):
    """Run one legacy-Expected-guarded call; return ('ok', None, None) or ('error', code, msg)."""
    expected = {'attr': condition}
    try:
        if op == 'Put':
            item = {'pk': {'S': pk}, 'attr': NEW, 'marker': {'S': 'applied'}}
            ddb.put_item(TableName=table, Item=item, Expected=expected)
        elif op == 'Delete':
            ddb.delete_item(TableName=table, Key={'pk': {'S': pk}}, Expected=expected)
        else:
            ddb.update_item(TableName=table, Key={'pk': {'S': pk}},
                             AttributeUpdates={'marker': {'Value': {'S': 'applied'}, 'Action': 'PUT'}},
                             Expected=expected)
    except ClientError as exc:
        err = exc.response['Error']
        return 'error', err['Code'], err['Message']
    return 'ok', None, None


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Every legacy Expected shape (Exists/Value/ComparisonOperator present or absent), against
    an attribute present and absent, is accepted, ConditionalCheckFailedException or
    ValidationException identically on PutItem, UpdateItem and DeleteItem.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.Expected.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                      AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                      BillingMode='PAY_PER_REQUEST',
                      Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    for case_name, expected, state, outcome in CASES:
        for op in OPERATIONS:
            pk = f'{case_name}-{op}'
            _setup_item(ddb, table, pk, state)
            kind, code, message = _apply(ddb, table, op, pk, expected)
            label = f'{case_name}/{op}'

            if outcome[0] == 'ok':
                assert kind == 'ok', f'{label}: expected success, got {code}: {message!r}'
            elif outcome[0] == 'ccfe':
                assert kind == 'error', f'{label}: expected {ERR_CONDITIONAL_CHECK_FAILED}, call succeeded'
                assert code == ERR_CONDITIONAL_CHECK_FAILED, f'{label}: expected {ERR_CONDITIONAL_CHECK_FAILED}, got {code}'
                assert message == ERR_CCFE_MESSAGE, f'{label}: expected AWS exact CCFE message, got {message!r}'
            else:
                assert kind == 'error', f'{label}: expected {ERR_VALIDATION}, call succeeded'
                assert code == ERR_VALIDATION, f'{label}: expected {ERR_VALIDATION}, got {code}'
                assert message == outcome[1], f'{label}: expected AWS exact ValidationException message, got {message!r}'

            got = ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')
            if outcome[0] == 'ok':
                if op == 'Delete':
                    assert got is None, f'{label}: a successful conditional DeleteItem left an item: {got!r}'
                elif op == 'Put':
                    assert got is not None and got.get('attr') == NEW and got.get('marker') == {'S': 'applied'}, (
                        f'{label}: a successful conditional PutItem did not land: {got!r}'
                    )
                else:
                    assert got is not None and got.get('marker') == {'S': 'applied'}, (
                        f'{label}: a successful conditional UpdateItem did not land: {got!r}'
                    )
            else:
                if state == 'absent':
                    assert got is not None and 'attr' not in got, (
                        f'{label}: a rejected call must not have created attr: {got!r}'
                    )
                else:
                    want = MATCH if state == 'match' else MISMATCH
                    assert got is not None and got.get('attr') == want, (
                        f'{label}: a rejected call must not have changed attr: {got!r}'
                    )
                assert got is not None and 'marker' not in got, (
                    f'{label}: a rejected call must not have set marker: {got!r}'
                )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
