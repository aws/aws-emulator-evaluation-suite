"""stale-condition-update-rejected-leaves-counter-and-audit-trail-intact."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stale-condition-update-rejected-leaves-counter-and-audit-trail-intact"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_RACERS = 16
_STALE_RACERS = 12
_MAX_ATTEMPTS = 200
_ERR_CCF = 'ConditionalCheckFailedException'
_KEY = {'pk': {'S': 'COUNTER#1'}}


def _error_code(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised.

    An unexpected success raises, so an accepted UpdateItem never reads as a code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code')
    raise AssertionError('the guarded UpdateItem succeeded against a stale expected value')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Concurrent UpdateItems with a stale condition all fail ConditionalCheckFailedException and
    neither the SET nor the list_append clause lands; the same call with the current value succeeds.
    """
    ddb = ctx.client('dynamodb', config=Config(max_pool_connections=_RACERS + 16,
                                               retries={'mode': 'standard', 'max_attempts': 5}))
    table = ctx.unique_name('sim2real-behav-d1-stale-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'd1-stale-condition'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'COUNTER#1'}, 'n': {'N': '0'}})

    def _update(worker: int, expected: int, nxt: int):
        return ddb.update_item(
            TableName=table, Key=_KEY,
            UpdateExpression=('SET #n = :next, '
                              '#a = list_append(if_not_exists(#a, :empty), :entry)'),
            ConditionExpression='#n = :expected',
            ExpressionAttributeNames={'#n': 'n', '#a': 'audit'},
            ExpressionAttributeValues={
                ':next': {'N': str(nxt)},
                ':expected': {'N': str(expected)},
                ':empty': {'L': []},
                ':entry': {'L': [{'M': {'worker': {'N': str(worker)},
                                        'before': {'N': str(expected)},
                                        'after': {'N': str(nxt)}}}]},
            },
        )

    # Racer arrival order is not guaranteed, so setup is asserted as a set and a count.
    def _racer(worker: int) -> str | None:
        for _ in range(_MAX_ATTEMPTS):
            cur = int(ddb.get_item(TableName=table, Key=_KEY,
                                   ConsistentRead=True)['Item']['n']['N'])
            try:
                _update(worker, cur, cur + 1)
                return None
            except ClientError as exc:
                code = exc.response.get('Error', {}).get('Code')
                if code != _ERR_CCF:
                    return f'worker {worker}: {code}'
        return f'worker {worker} exhausted its {_MAX_ATTEMPTS} attempt budget'

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        errors = [e for e in pool.map(_racer, range(_RACERS)) if e is not None]
    assert errors == [], f'the setup racers failed: {errors!r}'

    item = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert item['n']['N'] == str(_RACERS), (
        f'setup left the counter at {item["n"]["N"]!r}, expected {str(_RACERS)!r}'
    )
    audit_before = item['audit']['L']
    assert len(audit_before) == _RACERS, (
        f'setup left {len(audit_before)!r} audit entries, expected {_RACERS!r}'
    )
    workers_before = sorted(int(e['M']['worker']['N']) for e in audit_before)
    assert workers_before == list(range(_RACERS)), (
        f'setup audit workers are {workers_before!r}, expected 0..{_RACERS - 1!r} once each'
    )

    # :expected = 0 was true at seed time and is now stale.
    with ThreadPoolExecutor(max_workers=_STALE_RACERS) as pool:
        codes = list(pool.map(
            lambda w: _error_code(lambda: _update(900 + w, 0, 1)), range(_STALE_RACERS)))
    assert codes == [_ERR_CCF] * _STALE_RACERS, (
        f'{_STALE_RACERS!r} concurrent UpdateItem calls with a stale expected value returned '
        f'{codes!r}, expected {_ERR_CCF!r} for every one'
    )

    after = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert after['n']['N'] == str(_RACERS), (
        f'a rejected conditional UpdateItem still applied its SET clause: the counter reads '
        f'{after["n"]["N"]!r}, expected {str(_RACERS)!r}'
    )
    audit_after = after['audit']['L']
    assert len(audit_after) == _RACERS, (
        f'a rejected conditional UpdateItem still applied its list_append clause: the audit trail '
        f'holds {len(audit_after)!r} entries, expected {_RACERS!r}'
    )
    intruders = sorted(int(e['M']['worker']['N']) for e in audit_after
                       if int(e['M']['worker']['N']) >= 900)
    assert intruders == [], (
        f'the audit trail carries entries from workers whose update was rejected: {intruders!r}'
    )
    assert audit_after == audit_before, (
        f'the rejected updates rewrote the audit trail: {len(audit_before)!r} entries became '
        f'{len(audit_after)!r} with different content'
    )

    _update(999, _RACERS, _RACERS + 1)
    final = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert final['n']['N'] == str(_RACERS + 1), (
        f'the control UpdateItem with a current expected value left the counter at '
        f'{final["n"]["N"]!r}, expected {str(_RACERS + 1)!r} -- the twelve rejections above were '
        f'not attributable to the condition'
    )
    assert len(final['audit']['L']) == _RACERS + 1, (
        f'the control UpdateItem left {len(final["audit"]["L"])!r} audit entries, expected '
        f'{_RACERS + 1!r}'
    )
    assert int(final['audit']['L'][-1]['M']['worker']['N']) == 999, (
        f'the control entry is not the last appended: trail tail is '
        f'{final["audit"]["L"][-1]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
