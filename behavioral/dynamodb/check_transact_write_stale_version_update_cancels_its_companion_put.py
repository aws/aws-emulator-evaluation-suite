"""transact-write-stale-version-update-cancels-its-companion-put."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-stale-version-update-cancels-its-companion-put"
GROUP = 'e2e_workflows'
SERVICES = ['dynamodb']
ERR_CANCELED = 'TransactionCanceledException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems whose version-guarded Update is stale is cancelled with per-item reasons
    [ConditionalCheckFailed, None] and writes neither item; the same transaction with the current
    version commits the version bump and the companion Put together.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table))
    _wait_table_active(ddb, table)

    account = {'id': {'S': 'account-7'}, 'version': {'N': '41'}, 'balance': {'N': '100'}}
    ddb.put_item(TableName=table, Item=account)
    entry_key = {'id': {'S': 'ledger-7-42'}}

    def transfer(expected_version):
        return ddb.transact_write_items(TransactItems=[
            {'Update': {
                'TableName': table, 'Key': {'id': account['id']},
                'UpdateExpression': 'SET version = version + :one, balance = balance - :amt',
                'ConditionExpression': 'version = :v',
                'ExpressionAttributeValues': {':one': {'N': '1'}, ':amt': {'N': '30'},
                                              ':v': {'N': str(expected_version)}},
            }},
            {'Put': {
                'TableName': table,
                'Item': {**entry_key, 'amount': {'N': '30'}},
                'ConditionExpression': 'attribute_not_exists(id)',
            }},
        ])

    for stale in (40, 42):
        exc = _expect_error(lambda stale=stale: transfer(stale), (ERR_CANCELED,))
        message = exc.response['Error'].get('Message')
        assert message == ('Transaction cancelled, please refer cancellation reasons for specific '
                           'reasons [ConditionalCheckFailed, None]'), (
            f"the transaction expecting version {stale}: got the message {message!r}"
        )
        reasons = [(r.get('Code'), r.get('Message')) for r in exc.response.get('CancellationReasons', [])]
        assert reasons == [('ConditionalCheckFailed', 'The conditional request failed'), ('None', None)], (
            f"the transaction expecting version {stale}: got the cancellation reasons {reasons!r}"
        )
        _assert_state(ddb, table, account, entry_key, None, f'the cancelled version-{stale} transaction')

    transfer(41)
    committed = {**account, 'version': {'N': '42'}, 'balance': {'N': '70'}}
    _assert_state(ddb, table, committed, entry_key, {**entry_key, 'amount': {'N': '30'}},
                  'the committed transaction')

    # Replaying the committed transaction now fails both guards.
    exc = _expect_error(lambda: transfer(41), (ERR_CANCELED,))
    message = exc.response['Error'].get('Message')
    assert message == ('Transaction cancelled, please refer cancellation reasons for specific '
                       'reasons [ConditionalCheckFailed, ConditionalCheckFailed]'), (
        f"the replayed transaction: got the message {message!r}"
    )
    _assert_state(ddb, table, committed, entry_key, {**entry_key, 'amount': {'N': '30'}},
                  'the replayed transaction')


def _assert_state(ddb, table, account, entry_key, entry, after) -> None:
    got = ddb.get_item(TableName=table, Key={'id': account['id']}, ConsistentRead=True).get('Item')
    assert got == account, f"after {after}: expected the account {account!r}, got {got!r}"
    got_entry = ddb.get_item(TableName=table, Key=entry_key, ConsistentRead=True).get('Item')
    assert got_entry == entry, f"after {after}: expected the ledger entry {entry!r}, got {got_entry!r}"


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
