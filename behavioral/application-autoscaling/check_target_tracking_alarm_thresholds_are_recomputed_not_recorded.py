"""target-tracking-alarm-thresholds-are-recomputed-not-recorded."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Real AWS: scale_out == TargetValue/100 * Period * provisioned, and scale_in is NOT half of it
# but (TargetValue - 20)/100 * Period * provisioned -- a fixed 20-point buffer that scales with
# provisioned capacity (at provisioned=1 a flat raw-unit offset would look the same).

CHECK = "target-tracking-alarm-thresholds-are-recomputed-not-recorded"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_ALARM_SETTLE_S = 45.0
_TOLERANCE = 1e-6
_NAME_RE = re.compile(r'^TargetTracking-(?P<rid>.+)-(?P<kind>[A-Za-z]+)-'
                      r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
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


def _alarms_by_kind(cw, resource_id):
    """Independent enumeration at CloudWatch, keyed by the kind parsed out of the alarm name."""
    prefix = f'TargetTracking-{resource_id}-'
    out = {}
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
                f'TargetTracking-<resourceId>-<kind>-<uuid> grammar this check parses kinds out '
                f'of; alarm discovery is broken, so no verdict is possible'
            )
            out[match.group('kind')] = alarm
        token = page.get('NextToken')
        if not token:
            return out


def _sweep_alarms(cw, resource_id):
    names = [alarm['AlarmName'] for alarm in _alarms_by_kind(cw, resource_id).values()]
    if not names:
        return
    try:
        cw.delete_alarms(AlarmNames=names)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("ResourceNotFound",):
            raise RuntimeError(f'alarms {names!r} not deleted: '
                               f'{exc.response.get("Error", {}).get("Code")}') from exc


def _split_pairs(by_kind):
    """Return (utilisation_high, utilisation_low, provisioned_alarms) from the alarms' fields.

    The utilisation pair is the one whose two sides carry DIFFERENT thresholds; the
    provisioned-capacity pair carries the same threshold on both sides. Structural, so no alarm
    name is trusted.
    """
    per_metric = {}
    for alarm in by_kind.values():
        per_metric.setdefault(alarm['MetricName'], []).append(alarm)
    asymmetric = sorted(
        metric for metric, alarms in per_metric.items()
        if len({a['ComparisonOperator'] for a in alarms}) == 2
        and len({a['Threshold'] for a in alarms}) == 2
    )
    shape = {k: (a['MetricName'], a['ComparisonOperator'], a['Threshold'], a['Period'])
             for k, a in by_kind.items()}
    assert len(asymmetric) == 1, (
        f'expected exactly one metric with a two-sided pair of DIFFERENT thresholds -- the '
        f'utilisation pair -- but found {asymmetric!r} in {shape!r}'
    )
    util = per_metric[asymmetric[0]]
    high = [a for a in util if a['ComparisonOperator'] == 'GreaterThanThreshold']
    low = [a for a in util if a['ComparisonOperator'] == 'LessThanThreshold']
    assert len(high) == 1 and len(low) == 1, (
        f'the utilisation pair on {asymmetric[0]!r} is not one alarm per side: {shape!r}'
    )
    provisioned = [a for metric, alarms in per_metric.items() if metric != asymmetric[0]
                   for a in alarms]
    return high[0], low[0], provisioned


def _read_capacity(ddb, table):
    return ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits']


def _assert_rule(cw, ddb, resource_id, table, target_value, *, leg):
    """Assert the whole derived relation at one (TargetValue, provisioned) point.

    Returns (scale_out, scale_in, provisioned) so the caller can prove the numbers MOVED between
    legs; the equalities alone hold for a target that never recomputes.
    """
    provisioned = _read_capacity(ddb, table)
    want_high = target_value / 100.0 * 60.0 * provisioned

    def _matches(by_kind):
        if len(by_kind) < 3:
            return False
        high, _low, _prov = _split_pairs(by_kind)
        return abs(high['Threshold'] - target_value / 100.0 * high['Period'] * provisioned) \
            <= _TOLERANCE

    by_kind = _poll_until(
        lambda: _alarms_by_kind(cw, resource_id), _matches,
        timeout_s=_ALARM_SETTLE_S, interval_s=3.0,
        description=f'{leg}: the utilisation scale-out threshold settling on '
                    f'{target_value}% * Period * {provisioned} provisioned units '
                    f'(== {want_high} at the measured Period of 60 s)')
    high, low, provisioned_alarms = _split_pairs(by_kind)

    expected_high = target_value / 100.0 * high['Period'] * provisioned
    assert abs(high['Threshold'] - expected_high) <= _TOLERANCE, (
        f'{leg}: the scale-out alarm threshold is {high["Threshold"]!r}; a TargetValue of '
        f'{target_value} against {provisioned} provisioned units aggregated as '
        f'{high["Statistic"]!r} over {high["Period"]}s derives '
        f'{target_value}/100 * {high["Period"]} * {provisioned} == {expected_high}'
    )
    expected_low = (target_value - 20.0) / 100.0 * high['Period'] * provisioned
    assert abs(low['Threshold'] - expected_low) <= _TOLERANCE, (
        f'{leg}: the scale-in alarm threshold is {low["Threshold"]!r}, expected '
        f'({target_value} - 20)/100 * {high["Period"]} * {provisioned} == {expected_low} -- '
        f'real AWS buffers scale-in by a fixed 20 PERCENTAGE POINTS below the target value, not '
        f'by halving the scale-out threshold'
    )
    assert low['Period'] == high['Period'], (
        f'{leg}: the two utilisation alarms disagree on Period '
        f'({high["Period"]} vs {low["Period"]}), so the derived thresholds are not comparable'
    )
    assert low['EvaluationPeriods'] > high['EvaluationPeriods'], (
        f'{leg}: the scale-in alarm evaluates over {low["EvaluationPeriods"]} periods and the '
        f'scale-out alarm over {high["EvaluationPeriods"]}; real AWS makes scale in strictly '
        f'more conservative than scale out'
    )
    for alarm in provisioned_alarms:
        assert abs(alarm['Threshold'] - float(provisioned)) <= _TOLERANCE, (
            f'{leg}: the provisioned-capacity alarm {alarm["AlarmName"]!r} has threshold '
            f'{alarm["Threshold"]!r}; it watches the provisioned figure itself, which is '
            f'{provisioned}'
        )
    return high['Threshold'], low['Threshold'], provisioned


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """Target-tracking alarms on a DynamoDB table set scale-out to TargetValue/100 * Period * capacity and
    scale-in to (TargetValue - 20)/100 * Period * capacity, and both thresholds rise when the target
    value is upserted (40 to 80) and when the capacity floor moves the table from 1 to 4 units."""
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    account = ctx.client('sts').get_caller_identity()['Account']

    table = ctx.unique_name('sim2real-behav-aas-thr-')
    policy = ctx.unique_name('sim2real-behav-aas-thrpol-')
    resource_id = f'table/{table}'

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')

    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=10,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    ctx.on_cleanup(lambda: _sweep_alarms(cw, resource_id))

    def _put(target_value):
        aas.put_scaling_policy(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            PolicyName=policy, PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': target_value,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
                'ScaleOutCooldown': 0, 'ScaleInCooldown': 0},
        )

    # ---- Leg 1: 40% against 1 provisioned unit.
    _put(40.0)
    ctx.on_cleanup(lambda: _delete_policy(aas, resource_id, policy))
    kinds_at_first_put = set(_alarms_by_kind(cw, resource_id))
    out_1, in_1, prov_1 = _assert_rule(cw, ddb, resource_id, table, 40.0,
                                       leg='leg 1 (TargetValue 40, capacity 1)')

    # ---- Leg 2: double the target value by UPSERT. Same policy name, no delete.
    _put(80.0)
    out_2, in_2, prov_2 = _assert_rule(cw, ddb, resource_id, table, 80.0,
                                       leg='leg 2 (TargetValue 80, capacity 1)')
    assert prov_2 == prov_1, (
        f'the table capacity moved from {prov_1} to {prov_2} during the target-value upsert, so '
        f'leg 2 no longer isolates the target value as the only changed input'
    )
    assert out_2 > out_1 and in_2 > in_1, (
        f'doubling TargetValue from 40 to 80 left the thresholds at '
        f'({out_2}, {in_2}) against ({out_1}, {in_1}); a target that RECORDED the first '
        f'thresholds instead of computing them answers exactly this way'
    )
    assert set(_alarms_by_kind(cw, resource_id)) == kinds_at_first_put, (
        f'the upsert changed which alarm kinds exist, from {sorted(kinds_at_first_put)!r} to '
        f'{sorted(_alarms_by_kind(cw, resource_id))!r}; a TargetValue change must rewrite the '
        f'same alarms, not mint a different inventory'
    )

    # ---- Leg 3: hold the target value and move the CAPACITY instead: raising MinCapacity drags
    # DynamoDB's ProvisionedThroughput up through Application Auto Scaling's own scaling activity.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=4, MaxCapacity=10)
    moved = _poll_until(lambda: _read_capacity(ddb, table), lambda cap: cap == 4,
                        timeout_s=150, interval_s=4.0,
                        description=f'DynamoDB provisioned read capacity for {table!r} being '
                                    f'dragged from {prov_2} up to the new floor of 4')
    assert moved == 4, (
        f'table {table!r} in region {ctx.region} of account {account} sits at {moved} read '
        f'capacity units; the new MinCapacity of 4 must reach DynamoDB before the alarm '
        f'thresholds can be expected to follow it'
    )
    out_3, in_3, prov_3 = _assert_rule(cw, ddb, resource_id, table, 80.0,
                                       leg='leg 3 (TargetValue 80, capacity 4)')
    assert prov_3 == 4, (
        f'the rule was evaluated against {prov_3} provisioned units, expected the 4 the floor '
        f'change produced'
    )
    assert out_3 > out_2 and in_3 > in_2, (
        f'quadrupling the provisioned capacity from {prov_2} to {prov_3} left the thresholds at '
        f'({out_3}, {in_3}) against ({out_2}, {in_2}); Application Auto Scaling must rewrite the '
        f'alarms after its own scaling activity, or the policy is tracking a stale utilisation'
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
