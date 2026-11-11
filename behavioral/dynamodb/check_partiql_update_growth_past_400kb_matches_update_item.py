"""partiql-update-growth-past-400kb-matches-update-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-growth-past-400kb-matches-update-item"
GROUP = 'limits'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
KB = 1024


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected SUCCESS raises rather than returning a falsy pair: a responder that
    ACCEPTS a growth real AWS refuses is the strongest signal this check can produce.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE that would grow an item past 400 KB raises ValidationException
    carrying the exact same code and message as the classic UpdateItem API for the same
    growth, and leaves nothing written; PartiQL UPDATE itself works on the same table.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-partiql-growth-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    oversized = 'x' * (401 * KB)

    # Positive control: PartiQL UPDATE works at all on this table, independent of size.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'control'}})
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET note = ? WHERE pk = ?',
        Parameters=[{'S': 'ok'}, {'S': 'control'}],
    )
    control = ddb.get_item(TableName=table, Key={'pk': {'S': 'control'}}, ConsistentRead=True).get('Item', {})
    assert control.get('note', {}).get('S') == 'ok', (
        f'positive control PartiQL UPDATE/GetItem round-trip failed, got {control!r}'
    )

    # The classic UpdateItem answer for this exact growth, on its own item.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'via-update-item'}})
    classic_code, classic_message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={'pk': {'S': 'via-update-item'}},
        UpdateExpression='SET bigattr = :v', ExpressionAttributeValues={':v': {'S': oversized}},
    ))
    assert classic_code == ERR_VALIDATION, (
        f'UpdateItem SET of a 401KB value must be {ERR_VALIDATION}, got {classic_code!r}'
    )
    assert classic_message == 'Item size to update has exceeded the maximum allowed size', (
        f'UpdateItem SET of a 401KB value must carry the exact AWS message, got {classic_message!r}'
    )
    after_classic = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'via-update-item'}}, ConsistentRead=True,
    ).get('Item', {})
    assert 'bigattr' not in after_classic, (
        f'a rejected UpdateItem SET must leave no trace, item is {after_classic!r}'
    )

    # The PartiQL UPDATE answer for the identical growth, on a different item.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'via-partiql'}})
    partiql_code, partiql_message = _code_and_message(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET bigattr = ? WHERE pk = ?',
        Parameters=[{'S': oversized}, {'S': 'via-partiql'}],
    ))
    assert partiql_code == ERR_VALIDATION, (
        f'PartiQL UPDATE growing past 400KB must be {ERR_VALIDATION}, got {partiql_code!r}'
    )
    after_partiql = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'via-partiql'}}, ConsistentRead=True,
    ).get('Item', {})
    assert 'bigattr' not in after_partiql, (
        f'a rejected PartiQL UPDATE must leave no trace, item is {after_partiql!r}'
    )

    # The two paths must name the exact same refusal for the exact same growth.
    assert partiql_code == classic_code, (
        f'PartiQL UPDATE error code {partiql_code!r} differs from UpdateItem error code '
        f'{classic_code!r} for the identical growth'
    )
    assert partiql_message == classic_message, (
        f"PartiQL UPDATE message {partiql_message!r} differs from UpdateItem's message "
        f'{classic_message!r} for the identical growth'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
