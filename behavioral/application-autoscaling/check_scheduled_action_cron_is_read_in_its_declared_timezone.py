"""scheduled-action-cron-is-read-in-its-declared-timezone."""
from __future__ import annotations

import datetime
import time
import zoneinfo
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-action-cron-is-read-in-its-declared-timezone"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_START_CAPACITY = 1
_SCHEDULED_MIN = 4
_SCHEDULED_MAX = 18
_MIN_LEAD_S = 40
_MIN_OFFSET_S = 3600
_MAX_OFFSET_S = 14 * 3600
# Bound for the scheduled dispatch plus its floor correction to complete.
_FIRE_S = 210.0
# Ordered by preference. The first entry whose CURRENT offset from UTC is at least +_MIN_OFFSET_S
# is used, so DST is resolved by the tz database at the instant the check runs rather than assumed.
# Every candidate is EAST of UTC on purpose: the naive arm reads the same wall clock as UTC, so an
# eastward zone puts that reading in the FUTURE and the one-shot cron is still acceptable.
_ZONE_CANDIDATES = ('Asia/Tokyo', 'Australia/Brisbane', 'Asia/Kolkata', 'Etc/GMT-9')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Poll probe() until predicate(result); raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _delete_table(ddb, name):
    for _ in range(8):
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException':
                raise RuntimeError(f'table {name!r} not deleted: {code}') from exc
            time.sleep(6)
    raise RuntimeError(f'table {name!r} still ResourceInUseException after retries')


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _delete_action(aas, resource_id, action):
    try:
        aas.delete_scheduled_action(ServiceNamespace=_NS, ResourceId=resource_id,
                                    ScalableDimension=_DIM, ScheduledActionName=action)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _create_provisioned_table(ddb, name, check_id):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': _START_CAPACITY, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': check_id},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {name!r} becoming ACTIVE')


def _activities(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _terminal(activity):
    return activity['StatusCode'] in ('Successful', 'Failed', 'Overridden', 'Unfulfilled')


def _read_capacity(ddb, table):
    return ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits']


def _cron_of(moment):
    """A one-shot Application Auto Scaling cron naming exactly one instant.

    The explicit year and day-of-month make the expression a single instant, never a recurrence.
    """
    return (f'cron({moment.minute} {moment.hour} {moment.day} {moment.month} ? '
            f'{moment.year})')


def _pick_zone(now_utc):
    """The first candidate zone currently between _MIN_OFFSET_S and _MAX_OFFSET_S east of UTC.

    The offset is read from the tz database at this instant, so daylight saving is not assumed.
    """
    tried = {}
    for name in _ZONE_CANDIDATES:
        offset = now_utc.astimezone(zoneinfo.ZoneInfo(name)).utcoffset()
        seconds = offset.total_seconds()
        tried[name] = seconds
        if _MIN_OFFSET_S <= seconds <= _MAX_OFFSET_S:
            return name, seconds
    raise AssertionError(
        f'no candidate zone is currently between +{_MIN_OFFSET_S}s and +{_MAX_OFFSET_S}s east of '
        f'UTC: {tried!r}. Without such a zone the naive arm\'s instant could fall inside this '
        f'check\'s own window and the negative would be meaningless'
    )


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control',
      'timing:real-time')
def run(ctx) -> None:
    """A scheduled action's cron is read in its declared Timezone: the zoned and UTC control arms
    fire at the target minute and reach DynamoDB, while the same string declared UTC stays pending.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/create-scheduled-actions.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    account = ctx.client('sts').get_caller_identity()['Account']

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    zone_name, offset_s = _pick_zone(now_utc)
    zone = zoneinfo.ZoneInfo(zone_name)

    fire_utc = now_utc.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire_utc - now_utc).total_seconds() < _MIN_LEAD_S:
        fire_utc += datetime.timedelta(minutes=1)
    fire_local = fire_utc.astimezone(zone)
    zoned_cron = _cron_of(fire_local)
    utc_cron = _cron_of(fire_utc)

    assert zoned_cron != utc_cron, (
        f'the zone {zone_name!r} (offset {offset_s}s) produced the same cron string {zoned_cron!r} '
        f'for the target instant {fire_utc.isoformat()} as UTC did; with identical strings the '
        f'naive arm is not a negative at all and this check would be vacuous'
    )
    naive_instant = fire_local.replace(tzinfo=datetime.timezone.utc)
    naive_delta = (naive_instant - fire_utc).total_seconds()
    assert naive_delta >= _MIN_OFFSET_S, (
        f'reading {zoned_cron!r} as UTC denotes {naive_instant.isoformat()}, only {naive_delta}s '
        f'after the target instant {fire_utc.isoformat()}; the naive arm must be at least '
        f'{_MIN_OFFSET_S}s outside this check\'s window for its silence to mean anything'
    )

    tables = {kind: ctx.unique_name(f'sim2real-behav-aas-tz-{kind}-')
              for kind in ('zoned', 'naive', 'control')}
    resource_ids = {kind: f'table/{name}' for kind, name in tables.items()}
    action = ctx.unique_name('sim2real-behav-aas-tzsa-')

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = []
        for name in tables.values():
            futures.append(pool.submit(_create_provisioned_table, ddb, name, CHECK))
            ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
        for future in futures:
            future.result()

    for resource_id in resource_ids.values():
        aas.register_scalable_target(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            MinCapacity=_START_CAPACITY, MaxCapacity=20,
            Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
        )
        ctx.on_cleanup(lambda r=resource_id: _deregister(aas, r))

    # All three actions are written in the same loop, so no arm gets a propagation head start.
    #   zoned   -- the zone's wall clock, declaring that zone. Must fire at fire_utc.
    #   naive   -- the SAME string, declaring UTC. Denotes fire_utc + offset. Must NOT fire.
    #   control -- UTC's wall clock, declaring UTC. Must fire at fire_utc, proving the scheduler
    #              is alive in this account in this very minute.
    arms = {
        'zoned': (zoned_cron, zone_name),
        'naive': (zoned_cron, 'UTC'),
        'control': (utc_cron, 'UTC'),
    }
    for kind, (schedule, timezone_name) in arms.items():
        aas.put_scheduled_action(
            ServiceNamespace=_NS, ResourceId=resource_ids[kind], ScalableDimension=_DIM,
            ScheduledActionName=action, Schedule=schedule, Timezone=timezone_name,
            ScalableTargetAction={'MinCapacity': _SCHEDULED_MIN, 'MaxCapacity': _SCHEDULED_MAX},
        )
        ctx.on_cleanup(lambda r=resource_ids[kind]: _delete_action(aas, r, action))
        stored = aas.describe_scheduled_actions(
            ServiceNamespace=_NS, ResourceId=resource_ids[kind],
            ScheduledActionNames=[action])['ScheduledActions']
        assert len(stored) == 1, (
            f'the {kind} arm stored {len(stored)} scheduled actions named {action!r}, expected '
            f'exactly 1: {stored!r}'
        )
        assert stored[0]['Schedule'] == schedule, (
            f'the {kind} arm came back carrying schedule {stored[0]["Schedule"]!r}, expected '
            f'{schedule!r}'
        )
        assert stored[0].get('Timezone') == timezone_name, (
            f'the {kind} arm came back carrying Timezone {stored[0].get("Timezone")!r}, expected '
            f'{timezone_name!r} verbatim'
        )

    # ---- Leg 1: both correctly-timed arms must fire at fire_utc. The control's arrival proves
    # the scheduler ran in this minute at all.
    for kind in ('control', 'zoned'):
        acts = _poll_until(
            lambda k=kind: _activities(aas, resource_ids[k]),
            lambda a: len(a) >= 2 and all(_terminal(x) for x in a),
            timeout_s=_FIRE_S, interval_s=5.0,
            description=f'the {kind} arm completing its scheduled chain -- the dispatch and the '
                        f'floor correction it causes -- for {fire_utc.isoformat()} '
                        f'({fire_local.isoformat()} in {zone_name})')
        causes = [a['Cause'] for a in acts]
        assert f'scheduled action name {action} was triggered' in causes, (
            f'the {kind} arm scaled for some other reason: {causes!r}'
        )
        assert f'minimum capacity was set to {_SCHEDULED_MIN}' in causes, (
            f'the {kind} arm never applied the scheduled floor of {_SCHEDULED_MIN}: {causes!r}'
        )
        dispatch = next(a for a in acts
                        if a['Cause'] == f'scheduled action name {action} was triggered')
        assert dispatch['Description'] == (
            f'Setting min capacity to {_SCHEDULED_MIN} and max capacity to {_SCHEDULED_MAX}'
        ), (
            f'the {kind} arm\'s dispatch described itself as {dispatch["Description"]!r}, expected '
            f'"Setting min capacity to {_SCHEDULED_MIN} and max capacity to {_SCHEDULED_MAX}"'
        )
        assert _read_capacity(ddb, tables[kind]) == _SCHEDULED_MIN, (
            f'the {kind} arm\'s table {tables[kind]!r} in region {ctx.region} of account '
            f'{account} is at {_read_capacity(ddb, tables[kind])} read capacity units; the '
            f'scheduled floor of {_SCHEDULED_MIN} must reach DynamoDB, not only the Application '
            f'Auto Scaling record'
        )

    # ---- Leg 2: and the naive arm -- identical cron string, wrong declared zone -- must be
    # untouched. Its instant is naive_delta seconds away, so this is a structural barrier.
    naive_acts = _activities(aas, resource_ids['naive'])
    assert naive_acts == [], (
        f'the naive arm recorded {len(naive_acts)} scaling activities '
        f'{[(a["Cause"], a["Description"], a["StatusCode"]) for a in naive_acts]!r}; it declares '
        f'Timezone "UTC" for a wall clock written in {zone_name!r}, so its instant is '
        f'{naive_instant.isoformat()} -- {naive_delta}s from now -- and nothing may have fired'
    )
    naive_target = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_ids['naive']])['ScalableTargets'][0]
    assert (naive_target['MinCapacity'], naive_target['MaxCapacity']) == (_START_CAPACITY, 20), (
        f'the naive arm\'s bounds moved to '
        f'({naive_target["MinCapacity"]}, {naive_target["MaxCapacity"]}); an action that has not '
        f'fired must not rewrite them to ({_SCHEDULED_MIN}, {_SCHEDULED_MAX})'
    )
    assert _read_capacity(ddb, tables['naive']) == _START_CAPACITY, (
        f'the naive arm\'s table {tables["naive"]!r} is at '
        f'{_read_capacity(ddb, tables["naive"])} read capacity units; an unfired scheduled action '
        f'must leave DynamoDB at {_START_CAPACITY}'
    )
    still_pending = aas.describe_scheduled_actions(
        ServiceNamespace=_NS, ResourceId=resource_ids['naive'],
        ScheduledActionNames=[action])['ScheduledActions']
    assert len(still_pending) == 1 and still_pending[0]['Schedule'] == zoned_cron, (
        f'the naive arm\'s scheduled action is no longer stored as one entry carrying '
        f'{zoned_cron!r}: {still_pending!r}. Its silence must be a pending action, not a missing '
        f'one'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
