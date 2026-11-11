"""dynamic-scaling-out-suspended-withholds-then-resume-delivers."""
from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dynamic-scaling-out-suspended-withholds-then-resume-delivers"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_TARGET_VALUE = 40.0
_START_CAPACITY = 1
_MAX_CAPACITY = 10
# Target-tracking scale-out on a DynamoDB table takes up to ~240 s to start.
_BARRIER_S = 240.0
_CAPACITY_S = 90.0
_RESUME_S = 150.0
_NAME_RE = re.compile(r'^TargetTracking-(?P<rid>.+)-(?P<kind>[A-Za-z]+)-'
                      r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
_ALL_RESUMED = {'DynamicScalingInSuspended': False, 'DynamicScalingOutSuspended': False,
                'ScheduledScalingSuspended': False}


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Poll *probe* until *predicate* accepts it; raise on timeout."""
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
    ddb.put_item(TableName=name, Item={'pk': {'S': 'hot'}, 'payload': {'S': 'x' * 512}})


def _activities(aas, resource_id, *, include_not_scaled=False):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM}
        if include_not_scaled:
            kwargs['IncludeNotScaledActivities'] = True
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _alarms_by_kind(cw, resource_id):
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
    """The utilisation scale-out alarm, derived from the alarms' own fields, not their names."""
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
    return candidates[0]


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


# timing:real-time — metric: 120 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:negative-classes',
      'concern:representation', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """DynamicScalingOutSuspended withholds a scale-out an unsuspended twin takes, keeps the alarms
    in place and in ALARM, and resuming delivers the withheld scale-out with no new metric movement.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-suspend-resume-scaling.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    account = ctx.client('sts').get_caller_identity()['Account']

    subject_table = ctx.unique_name('sim2real-behav-aas-so-susp-')
    control_table = ctx.unique_name('sim2real-behav-aas-so-ctrl-')
    subject_id = f'table/{subject_table}'
    control_id = f'table/{control_table}'
    policies = {}

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = []
        for name in (subject_table, control_table):
            futures.append(pool.submit(_create_provisioned_table, ddb, name, CHECK))
            ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
        for future in futures:
            future.result()

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=subject_id, ScalableDimension=_DIM,
        MinCapacity=_START_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        SuspendedState={'DynamicScalingInSuspended': False,
                        'DynamicScalingOutSuspended': True,
                        'ScheduledScalingSuspended': False},
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, subject_id))
    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=control_id, ScalableDimension=_DIM,
        MinCapacity=_START_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, control_id))

    echoed = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[subject_id])['ScalableTargets'][0]['SuspendedState']
    assert echoed == {'DynamicScalingInSuspended': False, 'DynamicScalingOutSuspended': True,
                      'ScheduledScalingSuspended': False}, (
        f'the subject reported SuspendedState {echoed!r}; only the dynamic scale-OUT flag was '
        f'set, and the other two must stay False or the withheld action is not attributable'
    )

    for resource_id in (subject_id, control_id):
        policy = ctx.unique_name('sim2real-behav-aas-sopol-')
        policies[resource_id] = policy
        aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': _TARGET_VALUE,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
                'ScaleOutCooldown': 0, 'ScaleInCooldown': 0},
        )
        ctx.on_cleanup(lambda r=resource_id, p=policy: _delete_policy(aas, r, p))
        ctx.on_cleanup(lambda r=resource_id: _sweep_alarms(cw, r))

    # Identical read load on both sides. SetAlarmState is no shortcut: target tracking re-reads
    # the metric itself, so an artificially ALARMed alarm produces no activity.
    stop = threading.Event()
    ctx.on_cleanup(stop.set)

    def _drive_read_load(table):
        while not stop.is_set():
            try:
                ddb.get_item(TableName=table, Key={'pk': {'S': 'hot'}}, ConsistentRead=True)
            except ClientError:
                time.sleep(0.2)

    for table in (subject_table, control_table):
        for _ in range(4):
            threading.Thread(target=_drive_read_load, args=(table,), daemon=True).start()

    # The control's capacity moving is the barrier for every absence claim about the subject.
    # Capture the alarm before polling: AWS recreates a target-tracking policy's alarms (new names,
    # recalibrated thresholds) as soon as the tracked capacity changes.
    control_alarm = _scale_out_alarm(_alarms_by_kind(cw, control_id), control_id)
    control_acts = _poll_until(
        lambda: [a for a in _activities(aas, control_id) if a['StatusCode'] == 'Successful'],
        bool, timeout_s=_BARRIER_S, interval_s=8.0,
        description=f'the unsuspended control {control_id!r} completing a scale-out under the '
                    f'same read load -- this arrival is the barrier for the suspended subject')
    assert control_acts[0]['Cause'] == (
        f'monitor alarm {control_alarm["AlarmName"]} in state ALARM triggered policy '
        f'{policies[control_id]}'
    ), (
        f'the control scale-out attributes itself to {control_acts[0]["Cause"]!r}; real AWS names '
        f'the alarm {control_alarm["AlarmName"]!r} and the policy {policies[control_id]!r}, and '
        f'without a policy-driven cause on the control side there is no barrier and no verdict'
    )
    control_capacity = _poll_until(
        lambda: _read_capacity(ddb, control_table),
        lambda cap: cap > _START_CAPACITY, timeout_s=_CAPACITY_S, interval_s=4.0,
        description=f'DynamoDB provisioned read capacity for the control {control_table!r} '
                    f'rising above {_START_CAPACITY}')
    assert control_capacity > _START_CAPACITY, (
        f'the control table sits at {control_capacity} read capacity units; the barrier requires '
        f'it to have grown past {_START_CAPACITY}'
    )

    # The subject withheld it while its own alarm is breached and all its alarms remain.
    subject_alarms = _alarms_by_kind(cw, subject_id)
    assert set(subject_alarms) == set(_alarms_by_kind(cw, control_id)), (
        f'the suspended subject has alarm kinds {sorted(subject_alarms)!r} while the control has '
        f'{sorted(_alarms_by_kind(cw, control_id))!r}; AWS documents that suspending dynamic '
        f'scaling does not delete the policies or their associated CloudWatch alarms, so removing '
        f'an alarm is the wrong implementation of the flag'
    )
    subject_alarm = _scale_out_alarm(subject_alarms, subject_id)
    breaching = _poll_until(
        lambda: _scale_out_alarm(_alarms_by_kind(cw, subject_id), subject_id)['StateValue'],
        lambda state: state == 'ALARM', timeout_s=_CAPACITY_S, interval_s=5.0,
        description=f'the suspended subject\'s own scale-out alarm '
                    f'{subject_alarm["AlarmName"]!r} entering ALARM, which is what makes the '
                    f'withheld scale-out attributable to the flag rather than to absent load')
    assert breaching == 'ALARM', (
        f'the subject\'s scale-out alarm {subject_alarm["AlarmName"]!r} is in state '
        f'{breaching!r}, so CloudWatch does not agree the threshold is breached and no conclusion '
        f'about the suspension can be drawn'
    )
    blocked = _activities(aas, subject_id)
    assert blocked == [], (
        f'the suspended subject recorded {len(blocked)} scaling activities while '
        f'DynamicScalingOutSuspended was set: '
        f'{[(a["Cause"], a["Description"], a["StatusCode"]) for a in blocked]!r}'
    )
    succeeded = [a for a in _activities(aas, subject_id, include_not_scaled=True)
                 if a['StatusCode'] == 'Successful']
    assert succeeded == [], (
        f'the suspended subject recorded a SUCCESSFUL scaling activity '
        f'{[(a["Cause"], a["Description"]) for a in succeeded]!r} even in the '
        f'IncludeNotScaledActivities view'
    )
    assert _read_capacity(ddb, subject_table) == _START_CAPACITY, (
        f'the suspended table {subject_table!r} in region {ctx.region} of account {account} is '
        f'provisioned at {_read_capacity(ddb, subject_table)} read capacity units; a withheld '
        f'scale-out must leave DynamoDB at {_START_CAPACITY} while the control has already '
        f'reached {control_capacity}'
    )

    # Resuming scale out re-evaluates policies whose alarms are currently in breach, so the
    # withheld scale-out needs no new metric movement.
    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=subject_id, ScalableDimension=_DIM,
        MinCapacity=_START_CAPACITY, MaxCapacity=_MAX_CAPACITY,
        SuspendedState=_ALL_RESUMED,
    )
    resumed_echo = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[subject_id])['ScalableTargets'][0]['SuspendedState']
    assert resumed_echo == _ALL_RESUMED, (
        f'the subject reported SuspendedState {resumed_echo!r} after being resumed, expected '
        f'{_ALL_RESUMED!r}'
    )
    delivered = _poll_until(
        lambda: [a for a in _activities(aas, subject_id) if a['StatusCode'] == 'Successful'],
        bool, timeout_s=_RESUME_S, interval_s=6.0,
        description=f'the withheld scale-out for {subject_id!r} being delivered after '
                    f'DynamicScalingOutSuspended was lifted, with the alarm still in ALARM')
    assert delivered[0]['Cause'] == (
        f'monitor alarm {subject_alarm["AlarmName"]} in state ALARM triggered policy '
        f'{policies[subject_id]}'
    ), (
        f'the delivered scale-out attributes itself to {delivered[0]["Cause"]!r}; it must be the '
        f'same policy-driven cause the control got, naming alarm '
        f'{subject_alarm["AlarmName"]!r} and policy {policies[subject_id]!r}'
    )
    subject_capacity = _poll_until(
        lambda: _read_capacity(ddb, subject_table),
        lambda cap: cap > _START_CAPACITY, timeout_s=_RESUME_S, interval_s=4.0,
        description=f'DynamoDB provisioned read capacity for the resumed {subject_table!r} '
                    f'finally rising above {_START_CAPACITY}')
    assert subject_capacity > _START_CAPACITY, (
        f'the resumed table {subject_table!r} is still at {subject_capacity} read capacity units; '
        f'resuming scale out must deliver the capacity that was withheld while the alarm was, and '
        f'still is, in breach'
    )
    assert delivered[0]['Description'] == f'Setting read capacity units to {subject_capacity}.', (
        f'the delivered activity described itself as {delivered[0]["Description"]!r} while '
        f'DynamoDB ended at {subject_capacity} read capacity units'
    )
    stop.set()


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
