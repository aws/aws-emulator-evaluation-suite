"""batch-request-items-key-not-a-table-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-request-items-key-not-a-table-name-rejected"
GROUP = 'batch'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_BAD_KEY = 'ab'


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A RequestItems map key that is not a legal table name (too short for the
    length-3 floor) is ValidationException for both BatchGetItem and BatchWriteItem,
    echoing the whole request value at 'requestItems'; an unrelated table is untouched.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    # Positive control: a well-formed batch write/read round trip works in this account,
    # so a rejection below is attributable to the malformed key, not to a broken client.
    ddb.batch_write_item(RequestItems={t: [{'PutRequest': {'Item': {'pk': {'S': 'control'}}}}]})
    got = ddb.scan(TableName=t, ConsistentRead=True)
    assert got['Items'] == [{'pk': {'S': 'control'}}], f'positive control not visible: {got}'

    code, message = _error(lambda: ddb.batch_get_item(
        RequestItems={_BAD_KEY: {'Keys': [{'pk': {'S': 'a'}}]}},
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "1 validation error detected: Value '{\"ab\":{\"Keys\":[{\"pk\":{\"S\":\"a\"}}]}}' at "
        "'requestItems' failed to satisfy constraint: Map keys must satisfy constraint: "
        "[Member must have length less than or equal to 255, Member must have length "
        "greater than or equal to 3, Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9_.-]+]"
    ), f'unexpected message {message!r}'

    # The item is empty: a non-empty item embeds its AttributeValue inside the echoed
    # value through a representation AWS itself does not keep stable across requests,
    # so an exact-message assertion must not depend on it.
    code, message = _error(lambda: ddb.batch_write_item(
        RequestItems={_BAD_KEY: [{'PutRequest': {'Item': {}}}]},
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "1 validation error detected: Value '{ab=[WriteRequest(putRequest=PutRequest("
        "item={}, workloadProfileName=null), deleteRequest=null)]}' at 'requestItems' "
        "failed to satisfy constraint: Map keys must satisfy constraint: [Member must "
        "have length less than or equal to 255, Member must have length greater than or "
        "equal to 3, Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+]"
    ), f'unexpected message {message!r}'

    after = ddb.scan(TableName=t, ConsistentRead=True)
    assert after['Items'] == [{'pk': {'S': 'control'}}], (
        f'the two rejected calls must leave the unrelated table unchanged, got {after["Items"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
