"""32-way-conditional-counter-no-lost-update-with-audit-trail."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "32-way-conditional-counter-no-lost-update-with-audit-trail"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_RACERS = 32
_MAX_ATTEMPTS = 200
_ERR_CCF = 'ConditionalCheckFailedException'
_MSG_CCF = 'The conditional request failed'
_KEY = {'pk': {'S': 'COUNTER#1'}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """32 concurrent read-then-conditional-UpdateItem increments leave the counter at 32 and an
    audit list whose before/after values form the unbroken chain 0->32 with no value claimed twice;
    any refused attempt is ConditionalCheckFailedException with its exact message.
    """
    ddb = ctx.client('dynamodb', config=Config(max_pool_connections=_RACERS + 8,
                                               retries={'mode': 'standard', 'max_attempts': 5}))
    table = ctx.unique_name('sim2real-behav-d1-cond-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={'pk': {'S': 'COUNTER#1'}, 'n': {'N': '0'}})
    seeded = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert seeded['n']['N'] == '0', f'the seeded counter reads {seeded["n"]["N"]!r}, expected "0"'
    assert 'audit' not in seeded, f'the seeded item already carries an audit list: {seeded!r}'

    def _racer(worker: int) -> tuple[int, int, str | None]:
        """Return (worker, conditional-check failures observed, error or None)."""
        rejections = 0
        for _ in range(_MAX_ATTEMPTS):
            item = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
            cur = int(item['n']['N'])
            try:
                ddb.update_item(
                    TableName=table, Key=_KEY,
                    UpdateExpression=('SET #n = :next, '
                                      '#a = list_append(if_not_exists(#a, :empty), :entry)'),
                    ConditionExpression='#n = :expected',
                    ExpressionAttributeNames={'#n': 'n', '#a': 'audit'},
                    ExpressionAttributeValues={
                        ':next': {'N': str(cur + 1)},
                        ':expected': {'N': str(cur)},
                        ':empty': {'L': []},
                        ':entry': {'L': [{'M': {'worker': {'N': str(worker)},
                                                'before': {'N': str(cur)},
                                                'after': {'N': str(cur + 1)}}}]},
                    },
                )
                return worker, rejections, None
            except ClientError as exc:
                code = exc.response.get('Error', {}).get('Code')
                message = exc.response.get('Error', {}).get('Message')
                if (code, message) != (_ERR_CCF, _MSG_CCF):
                    return worker, rejections, f'worker {worker}: {code}: {message!r}'
                rejections += 1
        return worker, rejections, (
            f'worker {worker} exhausted its {_MAX_ATTEMPTS} attempt budget after '
            f'{rejections} ConditionalCheckFailedException(s)'
        )

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(_racer, range(_RACERS)))

    errors = [e for _, _, e in results if e is not None]
    assert errors == [], f'a racer failed to land its increment: {errors!r}'

    item = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert item['n']['N'] == str(_RACERS), (
        f'lost update: the counter reads {item["n"]["N"]!r} after {_RACERS!r} conditional '
        f'increments that each reported success, expected {str(_RACERS)!r}'
    )

    audit = item['audit']['L']
    assert len(audit) == _RACERS, (
        f'the audit trail written by the same UpdateItem calls holds {len(audit)!r} entries, '
        f'expected {_RACERS!r} -- the counter reached {_RACERS!r} without {_RACERS!r} applied '
        f'increments'
    )
    entries = [(int(e['M']['worker']['N']), int(e['M']['before']['N']), int(e['M']['after']['N']))
               for e in audit]

    workers = sorted(w for w, _, _ in entries)
    assert workers == list(range(_RACERS)), (
        f'the audit workers are {workers!r}; expected each of 0..{_RACERS - 1!r} exactly once'
    )
    befores = sorted(b for _, b, _ in entries)
    assert befores == list(range(_RACERS)), (
        f'two racers recorded the same predecessor value -- this is a LOST UPDATE. The `before` '
        f'values were {befores!r}, expected each of 0..{_RACERS - 1!r} exactly once'
    )
    afters = sorted(a for _, _, a in entries)
    assert afters == list(range(1, _RACERS + 1)), (
        f'the audit `after` values are {afters!r}, expected 1..{_RACERS!r}'
    )
    for worker, before, after in entries:
        assert after == before + 1, (
            f'worker {worker!r} recorded before={before!r} after={after!r}; an increment must '
            f'advance the counter by exactly one'
        )
    chain = sorted(entries, key=lambda e: e[1])
    for step, (worker, before, after) in enumerate(chain):
        assert (before, after) == (step, step + 1), (
            f'the audit trail is not an unbroken chain: sorted position {step!r} is worker '
            f'{worker!r} with before={before!r} after={after!r}, expected {step!r}->{step + 1!r}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
