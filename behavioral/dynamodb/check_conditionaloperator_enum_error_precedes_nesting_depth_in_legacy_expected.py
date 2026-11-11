"""conditionaloperator-enum-error-precedes-nesting-depth-in-legacy-expected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conditionaloperator-enum-error-precedes-nesting-depth-in-legacy-expected"
GROUP = 'legacy'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_DEPTH = ('1 validation error detected: Nesting Levels have exceeded supported limits: '
             'Attributes in the item have nested levels beyond supported limit')
MSG_BADOP = ('1 validation error detected: Failed to satisfy constraint: Member must satisfy '
             'enum value set: [ALL, OR]')


def _nest(levels: int):
    """A chain of `levels` maps around one scalar leaf, `levels + 1` levels deep in total."""
    value = {'S': 'leaf'}
    for _ in range(levels):
        value = {'M': {'k': value}}
    return value


def _code_and_message(fn):
    """fn()'s ValidationException (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A legacy Expected map whose AttributeValueList holds a document 39 levels past the
    nesting limit, combined with an invalid ConditionalOperator value, reports the
    ConditionalOperator enum error, not the nesting-depth error the deep value alone raises.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    deep = _nest(39)
    shallow = {'S': 'leaf'}

    def _seed(key):
        ddb.put_item(TableName=table, Item={'pk': {'S': key}, 'a': {'S': 'va'}, 'b': {'S': 'vb'}})

    def _current(key):
        return ddb.get_item(TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True)['Item']

    # Positive control: a valid 2-condition Expected with ConditionalOperator='AND' still
    # performs the conditional overwrite.
    _seed('ctrl')
    ddb.put_item(
        TableName=table, Item={'pk': {'S': 'ctrl'}, 'a': {'S': 'va2'}, 'b': {'S': 'vb2'}},
        Expected={
            'a': {'ComparisonOperator': 'EQ', 'AttributeValueList': [{'S': 'va'}]},
            'b': {'ComparisonOperator': 'EQ', 'AttributeValueList': [{'S': 'vb'}]},
        },
        ConditionalOperator='AND',
    )
    assert _current('ctrl')['a'] == {'S': 'va2'}, 'a valid conditional put must perform its overwrite'

    # Combined defect: a deep comparison value plus an invalid ConditionalOperator.
    _seed('combo')
    code, message = _code_and_message(lambda: ddb.put_item(
        TableName=table, Item={'pk': {'S': 'combo'}, 'a': {'S': 'overwritten'}, 'b': {'S': 'vb'}},
        Expected={
            'a': {'ComparisonOperator': 'EQ', 'AttributeValueList': [deep]},
            'b': {'ComparisonOperator': 'EQ', 'AttributeValueList': [shallow]},
        },
        ConditionalOperator='XOR',
    ))
    assert code == ERR_VALIDATION, f'combo: expected {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_BADOP, f'combo: expected the ConditionalOperator enum message, got {message!r}'
    assert _current('combo') == {'pk': {'S': 'combo'}, 'a': {'S': 'va'}, 'b': {'S': 'vb'}}, (
        'combo: the rejected put must leave the existing item untouched'
    )

    # The deep value alone (valid ConditionalOperator) raises the nesting-depth error instead.
    _seed('deep-only')
    code, message = _code_and_message(lambda: ddb.put_item(
        TableName=table, Item={'pk': {'S': 'deep-only'}, 'a': {'S': 'overwritten'}, 'b': {'S': 'vb'}},
        Expected={
            'a': {'ComparisonOperator': 'EQ', 'AttributeValueList': [deep]},
            'b': {'ComparisonOperator': 'EQ', 'AttributeValueList': [shallow]},
        },
        ConditionalOperator='OR',
    ))
    assert code == ERR_VALIDATION, f'deep-only: expected {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_DEPTH, f'deep-only: expected the nesting-depth message, got {message!r}'
    assert _current('deep-only') == {'pk': {'S': 'deep-only'}, 'a': {'S': 'va'}, 'b': {'S': 'vb'}}, (
        'deep-only: the rejected put must leave the existing item untouched'
    )

    # The bad ConditionalOperator alone (shallow comparison values) raises the same enum error
    # as the combined case, confirming the enum check wins, not the depth check.
    _seed('badop-only')
    code, message = _code_and_message(lambda: ddb.put_item(
        TableName=table, Item={'pk': {'S': 'badop-only'}, 'a': {'S': 'overwritten'}, 'b': {'S': 'vb'}},
        Expected={
            'a': {'ComparisonOperator': 'EQ', 'AttributeValueList': [shallow]},
            'b': {'ComparisonOperator': 'EQ', 'AttributeValueList': [shallow]},
        },
        ConditionalOperator='XOR',
    ))
    assert code == ERR_VALIDATION, f'badop-only: expected {ERR_VALIDATION}, got {code!r}'
    assert message == MSG_BADOP, f'badop-only: expected the ConditionalOperator enum message, got {message!r}'
    assert _current('badop-only') == {'pk': {'S': 'badop-only'}, 'a': {'S': 'va'}, 'b': {'S': 'vb'}}, (
        'badop-only: the rejected put must leave the existing item untouched'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
