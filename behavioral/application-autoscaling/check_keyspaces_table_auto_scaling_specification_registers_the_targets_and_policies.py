"""keyspaces-table-auto-scaling-specification-registers-the-targets-and-policies."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keyspaces-table-auto-scaling-specification-registers-the-targets-and-policies"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'cassandra'
_READ = 'cassandra:table:ReadCapacityUnits'
_WRITE = 'cassandra:table:WriteCapacityUnits'


def _setting(low, high, target, disable_scale_in):
    return {'autoScalingDisabled': False, 'minimumUnits': low, 'maximumUnits': high,
            'scalingPolicy': {'targetTrackingScalingPolicyConfiguration': {
                'targetValue': target, 'disableScaleIn': disable_scale_in}}}


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """A Keyspaces table created with an autoScalingSpecification registers both dimensions and one
    target-tracking policy per dimension with the requested bounds, target and scale-in setting;
    the read policy (scale-in disabled) has no AlarmLow, the write policy has all four alarms.
    """
    ks = ctx.client('keyspaces')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    keyspace = ctx.unique_name('sim2real_aas_ks_')
    table = 'sim2real_t'
    resource_id = f'keyspace/{keyspace}/table/{table}'
    ks.create_keyspace(keyspaceName=keyspace, tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace(ks, keyspace))
    _poll_until(lambda: _keyspace_exists(ks, keyspace), bool, timeout_s=120, interval_s=3.0,
                description=f'keyspace {keyspace!r} becoming readable')
    ks.create_table(
        keyspaceName=keyspace, tableName=table,
        schemaDefinition={'allColumns': [{'name': 'pk', 'type': 'text'}],
                          'partitionKeys': [{'name': 'pk'}]},
        capacitySpecification=_capacity(2, 2),
        autoScalingSpecification={
            'readCapacityAutoScaling': _setting(2, 6, 50.0, True),
            'writeCapacityAutoScaling': _setting(2, 5, 70.0, False)},
        tags=[{'key': 'sim2real', 'value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ks, keyspace, table))
    for dim in (_READ, _WRITE):
        ctx.on_cleanup(lambda dim=dim: _deregister(aas, resource_id, dim))
    ctx.on_cleanup(lambda: _delete_alarms(cw, f'TargetTracking-{resource_id}-'))
    _poll_until(lambda: _table_status(ks, keyspace, table),
                lambda s: s == 'ACTIVE', timeout_s=300, interval_s=5.0,
                description=f'table {keyspace}.{table} becoming ACTIVE')

    targets = sorted(
        (t['ScalableDimension'], t['MinCapacity'], t['MaxCapacity'], t['RoleARN'].split('/')[-1])
        for t in aas.describe_scalable_targets(ServiceNamespace=_NS,
                                               ResourceIds=[resource_id])['ScalableTargets'])
    role = 'AWSServiceRoleForApplicationAutoScaling_CassandraTable'
    assert targets == [(_READ, 2, 6, role), (_WRITE, 2, 5, role)], (
        f'the specification registered {targets!r}')

    policies = {p['ScalableDimension']: p for p in aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id)['ScalingPolicies']}
    assert sorted(policies) == [_READ, _WRITE], (
        f'policies exist for {sorted(policies)!r}, expected one per dimension')
    expected = {
        _READ: (50.0, 'CassandraReadCapacityUtilization', True,
                ['AlarmHigh', 'CassandraProvisionedCapacityHigh', 'CassandraProvisionedCapacityLow']),
        _WRITE: (70.0, 'CassandraWriteCapacityUtilization', False,
                 ['AlarmHigh', 'AlarmLow', 'CassandraProvisionedCapacityHigh',
                  'CassandraProvisionedCapacityLow']),
    }
    for dim, (target, metric, no_scale_in, alarm_kinds) in expected.items():
        p = policies[dim]
        assert (p['PolicyName'], p['PolicyType']) == (
            f'{keyspace}-{table}-scaling-policy', 'TargetTrackingScaling'), (
            f'the {dim} policy is {p["PolicyType"]} named '
            f'{p["PolicyName"].replace(keyspace, "<keyspace>")!r}')
        cfg = p['TargetTrackingScalingPolicyConfiguration']
        got = (cfg['TargetValue'], cfg['PredefinedMetricSpecification']['PredefinedMetricType'],
               cfg['DisableScaleIn'])
        assert got == (target, metric, no_scale_in), (
            f'the {dim} policy configuration is {got!r}, expected {(target, metric, no_scale_in)!r}')
        kinds = sorted(a['AlarmName'][len(f'TargetTracking-{resource_id}-'):].rsplit('-', 5)[0]
                       for a in p['Alarms'])
        assert kinds == alarm_kinds, f'the {dim} policy alarms are {kinds!r}, expected {alarm_kinds!r}'


def _delete_alarms(cw, prefix):
    left = []
    for page in cw.get_paginator('describe_alarms').paginate(AlarmNamePrefix=prefix):
        left.extend(a['AlarmName'] for a in page['MetricAlarms'])
    if left:
        cw.delete_alarms(AlarmNames=left)


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _keyspaces_table(ctx, *, read, write):
    """A fresh keyspace holding one PROVISIONED table, both ACTIVE; returns (keyspace, table)."""
    ks = ctx.client('keyspaces')
    keyspace = ctx.unique_name('sim2real_aas_ks_')
    table = 'sim2real_t'
    ks.create_keyspace(keyspaceName=keyspace, tags=[{'key': 'sim2real', 'value': CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace(ks, keyspace))
    _poll_until(lambda: _keyspace_exists(ks, keyspace), bool, timeout_s=120, interval_s=3.0,
                description=f'keyspace {keyspace!r} becoming readable')
    ks.create_table(
        keyspaceName=keyspace, tableName=table,
        schemaDefinition={'allColumns': [{'name': 'pk', 'type': 'text'}],
                          'partitionKeys': [{'name': 'pk'}]},
        capacitySpecification=_capacity(read, write),
        tags=[{'key': 'sim2real', 'value': CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table(ks, keyspace, table))
    _poll_until(lambda: _table_status(ks, keyspace, table),
                lambda s: s == 'ACTIVE', timeout_s=300, interval_s=5.0,
                description=f'table {keyspace}.{table} becoming ACTIVE')
    return keyspace, table


def _table_status(ks, keyspace, table):
    """The table's status; a table not yet readable after CreateTable reads as None."""
    try:
        return ks.get_table(keyspaceName=keyspace, tableName=table)['status']
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        return None


def _keyspace_exists(ks, keyspace):
    try:
        ks.get_keyspace(keyspaceName=keyspace)
        return True
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        return False


def _delete_table(ks, keyspace, table):
    deadline = time.monotonic() + 40
    while True:
        try:
            ks.delete_table(keyspaceName=keyspace, tableName=table)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ConflictException' or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _delete_keyspace(ks, keyspace):
    """Delete the keyspace; a table still being deleted inside it is a ConflictException."""
    deadline = time.monotonic() + 40
    while True:
        try:
            ks.delete_keyspace(keyspaceName=keyspace)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ConflictException' or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _deregister(aas, resource_id, dimension):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _activities(aas, resource_id, dimension):
    out, token = [], None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id,
                  'ScalableDimension': dimension}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _next_minute_at(min_lead_s=30):
    """A one-time at() expression for the next whole UTC minute at least ``min_lead_s`` away."""
    now = datetime.datetime.now(datetime.timezone.utc)
    fire = now.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
    if (fire - now).total_seconds() < min_lead_s:
        fire += datetime.timedelta(minutes=1)
    return f'at({fire:%Y-%m-%dT%H:%M:%S})', fire




def _capacity(read, write):
    """PROVISIONED at (read, write), or on-demand when both are None."""
    if read is None and write is None:
        return {'throughputMode': 'PAY_PER_REQUEST'}
    return {'throughputMode': 'PROVISIONED', 'readCapacityUnits': read,
            'writeCapacityUnits': write}


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
