"""transact-write-token-dedupes-under-concurrent-submission."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-token-dedupes-under-concurrent-submission"
GROUP = 'transactions'
SERVICES = ['dynamodb']

_SUBMITTERS = 6
_ITEMS_PER_TRANSACTION = 12
_ROUNDS = 4


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """One ClientRequestToken submitted concurrently by several callers applies its transaction exactly
    once to every item; at least one submitter succeeds and any refusal is TransactionInProgressException.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-txtoken-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # A wide transaction and a fresh token per round maximise the overlap window.
    for round_no in range(_ROUNDS):
        token = str(uuid.uuid4())
        prefix = f'round-{round_no}'
        items = [
            {'Update': {
                'TableName': table,
                'Key': {'pk': {'S': f'{prefix}#{i}'}},
                'UpdateExpression': 'ADD applied :one',
                'ExpressionAttributeValues': {':one': {'N': '1'}},
            }}
            for i in range(_ITEMS_PER_TRANSACTION)
        ]

        def _submit(_):
            try:
                ddb.transact_write_items(TransactItems=items, ClientRequestToken=token)
                return None
            except ClientError as exc:
                return exc.response.get('Error', {}).get('Code')

        with ThreadPoolExecutor(max_workers=_SUBMITTERS) as pool:
            refusals = [c for c in pool.map(_submit, range(_SUBMITTERS)) if c is not None]

        assert len(refusals) < _SUBMITTERS, f'round {round_no}: every submission was refused: {refusals!r}'
        other = [c for c in refusals if c != 'TransactionInProgressException']
        assert not other, (
            f'round {round_no}: an overlapping submission of one token may only be refused with '
            f'TransactionInProgressException, got {refusals!r}'
        )

        counts = {}
        for i in range(_ITEMS_PER_TRANSACTION):
            item = ddb.get_item(
                TableName=table, Key={'pk': {'S': f'{prefix}#{i}'}}, ConsistentRead=True,
            ).get('Item')
            assert item is not None, (
                f'round {round_no}: item {i!r} of a transaction that {_SUBMITTERS!r} callers '
                f'submitted is absent altogether'
            )
            counts[i] = item['applied']['N']

        over = {i: n for i, n in counts.items() if n != '1'}
        assert not over, (
            f'round {round_no}: one token means one application however many callers submitted it '
            f'concurrently, and it must hold for EVERY item in the transaction. These items were '
            f'applied a different number of times: {over!r} (expected every one at 1 after '
            f'{_SUBMITTERS!r} concurrent submissions)'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
