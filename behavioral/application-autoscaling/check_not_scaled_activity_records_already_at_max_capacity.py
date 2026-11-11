"""not-scaled-activity-records-already-at-max-capacity."""
from __future__ import annotations

import re
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-scaled-activity-records-already-at-max-capacity"
GROUP = 'scaling-activities'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_TARGET_VALUE = 10.0
_START_CAPACITY = 5
_RAISED_MAX = 10
_BREACH_S = 240.0
_FREEZE_READS = 4
_FREEZE_INTERVAL_S = 35.0
_REPAIR_S = 180.0
_NAME_RE = re.compile(r'^TargetTracking-(?P<rid>.+)-(?P<kind>[A-Za-z]+)-'
                      r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Bounded retry that raises on timeout, never returns its last value."""
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


def _delete_policy(aas, resource_id, policy):
    try:
        aas.delete_scaling_policy(ServiceNamespace=_NS, ResourceId=resource_id,
                                  ScalableDimension=_DIM, PolicyName=policy)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _activities(aas, resource_id, *, include_not_scaled):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id,
                  'ScalableDimension': _DIM,
                  'IncludeNotScaledActivities': include_not_scaled}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _default_activities(aas, resource_id):
    """DescribeScalingActivities with the flag ABSENT from the request, not set to False."""
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id,
                  'ScalableDimension': _DIM}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _not_scaled(activities):
    return [a for a in activities if a.get('NotScaledReasons')]


def _alarms_by_kind(cw, resource_id):
    """Independent enumeration at CloudWatch, keyed by the kind parsed out of the alarm name."""
    prefix = f'TargetTracking-{resource_id}-'
    found = {}
    token = None
    while True:
        kwargs = {'AlarmNamePrefix': prefix, 'AlarmTypes': ['MetricAlarm']}
        if token:
            kwargs['NextToken'] = token
        page = cw.describe_alarms(**kwargs)
        for alarm in page['MetricAlarms']:
            match = _NAME_RE.match(alarm['AlarmName'])
            assert match is not None, (
                f'alarm {alarm["AlarmName"]!r} does not match the '
                f'TargetTracking-<resourceId>-<kind>-<uuid> grammar; alarm discovery is broken'
            )
            found[match.group('kind')] = alarm
        token = page.get('NextToken')
        if not token:
            return found


def _scale_out_alarm(by_kind, resource_id):
    """The utilisation scale-out alarm: the GreaterThanThreshold side of the metric whose two
    thresholds differ (the provisioned-capacity pair shares one threshold).
    """
    per_metric = {}
    for alarm in by_kind.values():
        per_metric.setdefault(alarm['MetricName'], []).append(alarm)
    shape = {k: (a['MetricName'], a['ComparisonOperator'], a['Threshold'])
             for k, a in by_kind.items()}
    candidates = [
        a for alarms in per_metric.values() if len({x['Threshold'] for x in alarms}) == 2
        for a in alarms if a['ComparisonOperator'] == 'GreaterThanThreshold'
    ]
    assert len(candidates) == 1, (
        f'expected exactly one utilisation scale-out alarm for {resource_id!r} but the policy '
        f'provisioned {shape!r}'
    )
    return candidates[0]['AlarmName']


def _sweep_alarms(cw, resource_id):
    names = [a['AlarmName'] for a in _alarms_by_kind(cw, resource_id).values()]
    if not names:
        return
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("ResourceNotFound",):
            raise RuntimeError(f'alarms {names!r} not deleted: '
                               f'{exc.response.get("Error", {}).get("Code")}') from exc


def _read_capacity(ddb, table):
    return ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits']


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:negative-classes',
      'concern:representation', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """A scale-out blocked by MaxCapacity is recorded once as a Failed AlreadyAtMaxCapacity activity,
    visible only with IncludeNotScaledActivities; raising the maximum then delivers the scale-out.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scaling-activities.html
    Reference: https://docs.aws.amazon.com/autoscaling/application/APIReference/API_NotScaledReason.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    account = ctx.client('sts').get_caller_identity()['Account']

    table = ctx.unique_name('sim2real-behav-aas-nsr-')
    policy = ctx.unique_name('sim2real-behav-aas-nsrpol-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': _START_CAPACITY, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')
    ddb.put_item(TableName=table, Item={'pk': {'S': 'hot'}, 'payload': {'S': 'x' * 512}})

    # MaxCapacity is deliberately EQUAL to the live provisioned capacity, so the very first
    # breach has nowhere to go. That equality is the whole subject of the check.
    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=_START_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    ctx.on_cleanup(lambda: _sweep_alarms(cw, resource_id))
    registered = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'][0]
    assert registered['MaxCapacity'] == _read_capacity(ddb, table), (
        f'the target is registered with MaxCapacity {registered["MaxCapacity"]} against a table '
        f'provisioned at {_read_capacity(ddb, table)} read capacity units; this check requires '
        f'them EQUAL so that the first scale-out has nowhere to go'
    )

    aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration={
            'TargetValue': _TARGET_VALUE,
            'PredefinedMetricSpecification': {
                'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
            'ScaleOutCooldown': 0, 'ScaleInCooldown': 0},
    )
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy))
    minted = _poll_until(
        lambda: _alarms_by_kind(cw, resource_id), lambda found: len(found) >= 2,
        timeout_s=60, interval_s=3.0,
        description=f'the policy {policy!r} provisioning its alarms for {resource_id!r} in '
                    f'CloudWatch, read back by AlarmNamePrefix')
    alarm_name = _scale_out_alarm(minted, resource_id)

    # Real read load, not SetAlarmState: target tracking re-reads the metric itself when invoked,
    # so a forced ALARM over an idle table produces no activity.
    stop = threading.Event()
    ctx.on_cleanup(stop.set)

    def _drive_read_load():
        while not stop.is_set():
            try:
                ddb.get_item(TableName=table, Key={'pk': {'S': 'hot'}}, ConsistentRead=True)
            except ClientError:
                time.sleep(0.2)

    for _ in range(6):
        threading.Thread(target=_drive_read_load, daemon=True).start()

    # ---- Leg 1: the not-scaled decision is recorded, and only the flagged read shows it.
    withheld = _poll_until(
        lambda: _not_scaled(_activities(aas, resource_id, include_not_scaled=True)),
        bool, timeout_s=_BREACH_S, interval_s=10.0,
        description=f'a not-scaled activity for {resource_id!r} while the scale-out alarm '
                    f'{alarm_name!r} breaches against a MaxCapacity equal to the live capacity')
    assert len(withheld) == 1, (
        f'{len(withheld)} not-scaled activities were recorded for the first breach, expected '
        f'exactly one: '
        f'{[(a.get("Cause"), a.get("StatusCode"), a.get("NotScaledReasons")) for a in withheld]!r}'
    )
    entry = withheld[0]
    assert entry['StatusCode'] == 'Failed', (
        f'the not-scaled activity reports StatusCode {entry["StatusCode"]!r}; a decision not to '
        f'scale is recorded as "Failed", and reporting "Successful" would claim a scaling that '
        f'never happened'
    )
    assert entry['Cause'] == (
        f'monitor alarm {alarm_name} in state ALARM triggered policy {policy}'
    ), (
        f'the not-scaled activity attributes itself to {entry["Cause"]!r}; real AWS names the '
        f'alarm {alarm_name!r} and the policy {policy!r}'
    )
    assert entry['Description'] == 'Attempting to scale due to alarm triggered', (
        f'the not-scaled activity described itself as {entry["Description"]!r}, expected the '
        f'documented "Attempting to scale due to alarm triggered"'
    )
    reasons = entry['NotScaledReasons']
    assert len(reasons) == 1, (
        f'the not-scaled activity carries {len(reasons)} reasons {reasons!r}; being at the '
        f'ceiling is one reason'
    )
    reason = reasons[0]
    assert reason['Code'] == 'AlreadyAtMaxCapacity', (
        f'the reason code is {reason["Code"]!r}; the documented code for a scale-out blocked by '
        f'the registered maximum is "AlreadyAtMaxCapacity", and the other four documented codes '
        f'(AutoScalingAnticipatedFlapping, TargetServicePutResourceAsUnscalable, '
        f'AlreadyAtMinCapacity, AlreadyAtDesiredCapacity) all describe something else'
    )
    assert reason['MaxCapacity'] == registered['MaxCapacity'], (
        f'the reason reports MaxCapacity {reason["MaxCapacity"]!r}; it must be the '
        f'{registered["MaxCapacity"]} DescribeScalableTargets reports for this target, or the '
        f'record does not explain what blocked the scale-out'
    )
    # The docs say CurrentCapacity and MinCapacity might be present, so they are optional.
    if 'CurrentCapacity' in reason:
        assert reason['CurrentCapacity'] == _read_capacity(ddb, table), (
            f'the reason reports CurrentCapacity {reason["CurrentCapacity"]!r} while DynamoDB '
            f'reports {_read_capacity(ddb, table)} provisioned read capacity units'
        )
    if 'MinCapacity' in reason:
        assert reason['MinCapacity'] == registered['MinCapacity'], (
            f'the reason reports MinCapacity {reason["MinCapacity"]!r}, expected the registered '
            f'{registered["MinCapacity"]}'
        )

    # The flag is what makes the entry visible. Asserted at the same instant, on the same target,
    # so an empty default view is not a timing artifact.
    default_view = _default_activities(aas, resource_id)
    assert _not_scaled(default_view) == [], (
        f'DescribeScalingActivities WITHOUT IncludeNotScaledActivities returned '
        f'{len(_not_scaled(default_view))} not-scaled entries '
        f'{[a.get("NotScaledReasons") for a in _not_scaled(default_view)]!r}; the documented '
        f'default is to hide them, so the request flag would be doing nothing'
    )
    assert default_view == [], (
        f'the default view shows {len(default_view)} activities '
        f'{[(a.get("Cause"), a.get("StatusCode")) for a in default_view]!r}; the target is at its '
        f'ceiling and nothing may have scaled'
    )
    assert _read_capacity(ddb, table) == _START_CAPACITY, (
        f'table {table!r} in region {ctx.region} of account {account} is provisioned at '
        f'{_read_capacity(ddb, table)} read capacity units; a scale-out blocked by MaxCapacity '
        f'must leave DynamoDB at {_START_CAPACITY}'
    )

    # ---- Leg 2: the documented deduplication. The breach is still running; the reason has not
    # changed; the count must be exactly unchanged across several alarm periods.
    activity_id = entry['ActivityId']
    for read in range(_FREEZE_READS):
        # Reads spaced to span more than two of the scale-out alarm's 60 s periods.
        time.sleep(_FREEZE_INTERVAL_S)
        again = _not_scaled(_activities(aas, resource_id, include_not_scaled=True))
        assert len(again) == 1, (
            f'read {read + 1} of {_FREEZE_READS}, {(read + 1) * _FREEZE_INTERVAL_S:.0f}s into a '
            f'continuing breach: {len(again)} not-scaled activities exist, expected the one '
            f'first entry -- AWS documents that subsequent not-scaled activities do not generate '
            f'new entries unless the reason changes: '
            f'{[(a["ActivityId"], a["NotScaledReasons"]) for a in again]!r}'
        )
        assert again[0]['ActivityId'] == activity_id, (
            f'read {read + 1} of {_FREEZE_READS}: the single not-scaled entry is now '
            f'{again[0]["ActivityId"]!r}, not the {activity_id!r} first recorded; the entry was '
            f'replaced rather than deduplicated'
        )

    # ---- Leg 3: lift the ceiling and DEMAND the withheld scale-out. Without this the absence
    # above is indistinguishable from a policy that never fires.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=_RAISED_MAX)
    scaled = _poll_until(
        lambda: [a for a in _activities(aas, resource_id, include_not_scaled=True)
                 if not a.get('NotScaledReasons') and a['StatusCode'] == 'Successful'],
        bool, timeout_s=_REPAIR_S, interval_s=8.0,
        description=f'the withheld scale-out being delivered once MaxCapacity is raised from '
                    f'{_START_CAPACITY} to {_RAISED_MAX}, with load still running')
    grown = _poll_until(
        lambda: _read_capacity(ddb, table), lambda cap: cap > _START_CAPACITY,
        timeout_s=_REPAIR_S, interval_s=5.0,
        description=f'DynamoDB provisioned read capacity for {table!r} rising above '
                    f'{_START_CAPACITY} once the ceiling is lifted')
    assert grown > _START_CAPACITY, (
        f'table {table!r} is still at {grown} read capacity units after MaxCapacity was raised '
        f'to {_RAISED_MAX} under the same load that produced the AlreadyAtMaxCapacity record; '
        f'the earlier absence cannot be attributed to the ceiling'
    )
    assert grown <= _RAISED_MAX, (
        f'table {table!r} grew to {grown} read capacity units, past the raised MaxCapacity of '
        f'{_RAISED_MAX}'
    )
    assert scaled[0]['Description'] == f'Setting read capacity units to {grown}.', (
        f'the delivered scale-out described itself as {scaled[0]["Description"]!r} while DynamoDB '
        f'ended at {grown} read capacity units; the activity must name the capacity it set'
    )
    stop.set()


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
