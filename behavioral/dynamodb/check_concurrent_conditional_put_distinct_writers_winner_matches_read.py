"""concurrent-conditional-put-distinct-writers-winner-matches-read."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-conditional-put-distinct-writers-winner-matches-read"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_RACERS = 20
_KEY = {'pk': {'S': 'race'}}
_CCF = ('ConditionalCheckFailedException', 'The conditional request failed')


def _attempt(fn):
    """('ok', response, None) or ('err', code, message). Anything else propagates."""
    try:
        return ('ok', fn(), None)
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return ('err', err.get('Code'), err.get('Message'))


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """20 conditional PutItems on one new key, each with a distinct writer id: exactly one
    succeeds, the other 19 are refused ConditionalCheckFailedException with its exact message,
    and a consistent read returns the one writer id that was told it succeeded.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-condwin-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    writer_ids = [f'writer-{i}' for i in range(_RACERS)]

    def _racer(writer_id):
        return writer_id, _attempt(lambda: ddb.put_item(
            TableName=table,
            Item={'pk': {'S': 'race'}, 'writer': {'S': writer_id}},
            ConditionExpression='attribute_not_exists(pk)',
        ))

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        outcomes = [f.result() for f in [pool.submit(_racer, w) for w in writer_ids]]

    wins = [writer_id for writer_id, (kind, *_rest) in outcomes if kind == 'ok']
    losses = [(writer_id, code, message)
              for writer_id, (kind, code, message) in outcomes if kind == 'err']

    assert len(wins) == 1, f'expected exactly 1 winner among {_RACERS} writers, got {wins!r}'
    assert len(losses) == _RACERS - 1, (
        f'expected {_RACERS - 1} refusals, got {len(losses)}: {losses!r}'
    )
    for writer_id, code, message in losses:
        assert (code, message) == _CCF, (
            f'writer {writer_id!r} was refused with ({code!r}, {message!r}), expected {_CCF!r}'
        )

    landed = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True).get('Item')
    assert landed is not None, 'independent consistent GetItem found no item after one PutItem won'
    assert landed.get('writer') == {'S': wins[0]}, (
        f"the item's writer is {landed.get('writer')!r}, expected the winner's own id "
        f"{{'S': {wins[0]!r}}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
