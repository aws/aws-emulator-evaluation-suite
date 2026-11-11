"""string-revision-token-conditional-writes-refuse-stale-and-unissued-tokens."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "string-revision-token-conditional-writes-refuse-stale-and-unissued-tokens"
GROUP = 'e2e_workflows'
SERVICES = ['dynamodb']
ERR_CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException'
CCF_MESSAGE = 'The conditional request failed'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a composite-key item guarded by a string revision token, a put-if-absent of an existing key,
    a stale token, a never-issued token and a current token with a mismatched status are each refused
    and change nothing, while the current token rotates the revision and the payload.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'tenant', 'KeyType': 'HASH'},
                   {'AttributeName': 'doc', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'tenant', 'AttributeType': 'S'},
                              {'AttributeName': 'doc', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table))
    _wait_table_active(ddb, table)

    key = {'tenant': {'S': 'acme'}, 'doc': {'N': '907'}}
    rev1, rev2, rev3 = (ctx.unique_name(f'rev{i}-') for i in (1, 2, 3))
    first = {**key, 'rev': {'S': rev1}, 'status': {'S': 'open'}, 'body': {'S': 'draft'}}
    put_if_absent = {'ConditionExpression': 'attribute_not_exists(tenant)'}
    ddb.put_item(TableName=table, Item=first, **put_if_absent)
    exc = _expect_error(lambda: ddb.put_item(
        TableName=table, Item={**key, 'rev': {'S': 'other'}, 'body': {'S': 'clobber'}}, **put_if_absent),
        (ERR_CONDITIONAL_CHECK_FAILED,))
    assert exc.response['Error'].get('Message') == CCF_MESSAGE, exc.response['Error']
    _assert_item(ddb, table, key, first, 'the refused put-if-absent')

    def rotate(expected_rev, new_rev, body, status='open'):
        return ddb.update_item(
            TableName=table, Key=key,
            UpdateExpression='SET rev = :new, body = :body',
            ConditionExpression='rev = :expected AND #st = :status',
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={':new': {'S': new_rev}, ':body': {'S': body},
                                       ':expected': {'S': expected_rev}, ':status': {'S': status}},
            ReturnValues='ALL_NEW',
        )['Attributes']

    second = {**first, 'rev': {'S': rev2}, 'body': {'S': 'reviewed'}}
    assert rotate(rev1, rev2, 'reviewed') == second, "the current token did not rotate the revision"

    for label, token, status in (('stale', rev1, 'open'), ('never-issued', rev3, 'open'),
                                 ('current token, wrong status', rev2, 'closed')):
        exc = _expect_error(lambda token=token, status=status: rotate(token, rev3, 'lost', status),
                            (ERR_CONDITIONAL_CHECK_FAILED,))
        message = exc.response['Error'].get('Message')
        assert message == CCF_MESSAGE, f"the {label} update: got the message {message!r}"
        _assert_item(ddb, table, key, second, f'the refused {label} update')

    third = {**second, 'rev': {'S': rev3}, 'body': {'S': 'final'}}
    assert rotate(rev2, rev3, 'final') == third, "the current token did not rotate a second time"
    _assert_item(ddb, table, key, third, 'the second rotation')
    # A sibling key in the same partition was never written by any of the refused calls.
    other = ddb.get_item(TableName=table, Key={'tenant': {'S': 'acme'}, 'doc': {'N': '908'}},
                         ConsistentRead=True)
    assert 'Item' not in other, f"an unrelated key appeared: {other.get('Item')!r}"


def _assert_item(ddb, table, key, want, after) -> None:
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert got == want, f"after {after}: expected {want!r}, got {got!r}"


def _delete_table_if_exists(ddb, table) -> None:
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


def _assert_error(exc, codes, *, status=400) -> None:
    """Grade a ClientError on code, HTTP status class and a non-empty message."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx with {code}, got {got_status!r}"
    )
    assert msg.strip(), f"expected a non-empty message with {code}"


def _expect_error(fn, codes, *, status=400):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


#: Bound on each wait; a target that needs longer fails with the last answer it gave.
_WAIT_S = 40.0


def _wait_table_active(ddb, table, timeout_s=_WAIT_S) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last TableStatus {status!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
