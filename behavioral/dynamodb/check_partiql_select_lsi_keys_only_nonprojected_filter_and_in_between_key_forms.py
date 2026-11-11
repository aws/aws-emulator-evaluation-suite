"""partiql-select-lsi-keys-only-nonprojected-filter-and-in-between-key-forms."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-lsi-keys-only-nonprojected-filter-and-in-between-key-forms"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_INDEX = 'lsi1'


def _error_code(fn) -> str:
    """The Error.Code and Error.Message ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the statement to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT on a KEYS_ONLY LSI with a WHERE term on a non-key attribute is a
    ValidationException, while IN and BETWEEN on the index's own sort key both answer as key
    conditions, not as refused forms.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqllsi-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [
                {'AttributeName': 'pk', 'KeyType': 'HASH'},
                {'AttributeName': 'lsk', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    for sk, lsk in [('s1', 1), ('s2', 2), ('s3', 3), ('s4', 4)]:
        ddb.put_item(TableName=table, Item={
            'pk': {'S': 'P'}, 'sk': {'S': sk}, 'lsk': {'N': str(lsk)}, 'body': {'S': f'body-{sk}'},
        })

    # Positive control: the index-key equality alone reaches the item through the index, proving
    # the WHERE below is being evaluated against the index rather than failing some other way.
    baseline = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE pk = 'P' AND lsk = 1",
        ConsistentRead=True,
    ).get('Items', [])
    assert baseline == [{'pk': {'S': 'P'}, 'sk': {'S': 's1'}, 'lsk': {'N': '1'}}], (
        f'KEYS_ONLY must project only the table and index keys, got {baseline!r}'
    )

    # A WHERE term on an attribute the KEYS_ONLY projection does not hold is rejected, not
    # silently served from the base table.
    code, message = _error_code(lambda: ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE pk = 'P' AND body = 'body-s1'",
        ConsistentRead=True,
    ))
    assert code == 'ValidationException', (
        f'a WHERE term on a non-projected attribute of a KEYS_ONLY index must be refused with '
        f'ValidationException, got {code}: {message!r}'
    )
    assert message == (
        f'One or more parameter values were invalid: Secondary index {_INDEX} does not project '
        f'one or more filter attributes: [body]'
    ), f"expected AWS's exact ValidationException message, got {message!r}"

    # IN on the index's own sort key, alongside the partition key equality, answers rather than
    # being refused as an illegal key-condition form.
    in_items = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE pk = 'P' AND lsk IN [1, 3]",
        ConsistentRead=True,
    ).get('Items', [])
    in_keys = sorted(i['sk']['S'] for i in in_items)
    assert in_keys == ['s1', 's3'], f'lsk IN [1, 3] must answer with sk s1 and s3, got {in_keys!r}'

    # BETWEEN on the index's own sort key likewise answers.
    between_items = ddb.execute_statement(
        Statement=f"SELECT * FROM \"{table}\".\"{_INDEX}\" WHERE pk = 'P' AND lsk BETWEEN 2 AND 3",
        ConsistentRead=True,
    ).get('Items', [])
    between_keys = sorted(i['sk']['S'] for i in between_items)
    assert between_keys == ['s2', 's3'], (
        f'lsk BETWEEN 2 AND 3 must answer with sk s2 and s3, got {between_keys!r}'
    )

    # The rejected SELECT above is read-only: every base-table item is exactly as written.
    kept = ddb.get_item(TableName=table, Key={'pk': {'S': 'P'}, 'sk': {'S': 's1'}}, ConsistentRead=True)['Item']
    assert kept == {'pk': {'S': 'P'}, 'sk': {'S': 's1'}, 'lsk': {'N': '1'}, 'body': {'S': 'body-s1'}}, (
        f'the rejected SELECT must not have written anything; item now reads {kept!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
