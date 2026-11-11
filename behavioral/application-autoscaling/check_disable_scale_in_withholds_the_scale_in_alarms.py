"""disable-scale-in-withholds-the-scale-in-alarms."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-scale-in-withholds-the-scale-in-alarms"
GROUP = 'scaling-policies'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_TARGET_VALUE = 40.0
_ALARM_SETTLE_S = 30.0  # alarm creation/removal is asynchronous to PutScalingPolicy
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
    """Delete the table, tolerating the UPDATING window a scaling activity leaves behind."""
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
        ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': check_id},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {name!r} becoming ACTIVE')


def _alarms_by_kind(cw, resource_id):
    """TargetTracking alarms for resource_id read from CloudWatch, keyed by the kind in the name.

    Not built from PutScalingPolicy's Alarms array, so an echoed array with nothing behind it fails.
    """
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
            assert match.group('rid') == resource_id, (
                f'alarm {alarm["AlarmName"]!r} claims resource id {match.group("rid")!r} but was '
                f'returned under the AlarmNamePrefix for {resource_id!r}'
            )
            out[match.group('kind')] = alarm
        token = page.get('NextToken')
        if not token:
            return out


def _sweep_alarms(cw, resource_id):
    """Delete only the alarms Application Auto Scaling minted for THIS check's resource id."""
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


def _utilisation_metric(by_kind):
    """The utilisation metric: the only one whose high and low alarm thresholds differ.

    The provisioned-capacity pair uses the same threshold on both sides, so it cannot match.
    """
    per_metric = {}
    for alarm in by_kind.values():
        per_metric.setdefault(alarm['MetricName'], {}).setdefault(
            alarm['ComparisonOperator'], set()).add(alarm['Threshold'])
    asymmetric = sorted(
        metric for metric, sides in per_metric.items()
        if 'GreaterThanThreshold' in sides and 'LessThanThreshold' in sides
        and sides['GreaterThanThreshold'] != sides['LessThanThreshold']
    )
    assert len(asymmetric) == 1, (
        f'expected exactly one metric with a two-sided pair of DIFFERENT thresholds -- the '
        f'utilisation pair -- but found {asymmetric!r} in {per_metric!r}; the derivation this '
        f'check uses to locate the scale-in trigger without naming it is ambiguous here'
    )
    return asymmetric[0]


def _scale_in_kind(by_kind, utilisation_metric):
    """The alarm kind that TRIGGERS scale in, identified from the alarms' own fields."""
    found = sorted(
        kind for kind, alarm in by_kind.items()
        if alarm['MetricName'] == utilisation_metric
        and alarm['ComparisonOperator'] == 'LessThanThreshold'
    )
    shape = {k: (a['MetricName'], a['ComparisonOperator'], a['Threshold'])
             for k, a in by_kind.items()}
    assert len(found) == 1, (
        f'expected exactly one scale-in trigger -- an alarm on {utilisation_metric!r} with '
        f'ComparisonOperator LessThanThreshold -- but found {found!r} among {shape!r}'
    )
    return found[0]


def _put_policy(aas, resource_id, policy, *, disable_scale_in):
    config = {
        'TargetValue': _TARGET_VALUE,
        'PredefinedMetricSpecification': {
            'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'},
    }
    if disable_scale_in is not None:
        config['DisableScaleIn'] = disable_scale_in
    return aas.put_scaling_policy(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyName=policy, PolicyType='TargetTrackingScaling',
        TargetTrackingScalingPolicyConfiguration=config,
    )


def _stored_config(aas, resource_id, policy):
    stored = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyNames=[policy])['ScalingPolicies']
    assert len(stored) == 1, (
        f'DescribeScalingPolicies returned {len(stored)} policies named {policy!r} on '
        f'{resource_id!r}, expected exactly 1: {stored!r}'
    )
    return stored[0]['TargetTrackingScalingPolicyConfiguration']


@tags('axis:happy-path', 'cap:c1', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """DisableScaleIn=True provisions a strict subset of a twin policy's alarms, minus the scale-in
    trigger, and flipping the flag by upsert re-mints and removes that alarm in CloudWatch.
    """
    # The alarm inventory stands in for an observed scale-in: the low alarm needs 15 x 60 s periods.
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    cw = ctx.client('cloudwatch')
    account = ctx.client('sts').get_caller_identity()['Account']

    control_table = ctx.unique_name('sim2real-behav-aas-dsi-ctrl-')
    subject_table = ctx.unique_name('sim2real-behav-aas-dsi-subj-')
    control_id = f'table/{control_table}'
    subject_id = f'table/{subject_table}'
    control_policy = ctx.unique_name('sim2real-behav-aas-dsi-ctrlpol-')
    subject_policy = ctx.unique_name('sim2real-behav-aas-dsi-subjpol-')

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = []
        for name in (control_table, subject_table):
            futures.append(pool.submit(_create_provisioned_table, ddb, name, CHECK))
            ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
        for future in futures:
            future.result()

    for resource_id in (control_id, subject_id):
        aas.register_scalable_target(
            ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
            MinCapacity=1, MaxCapacity=10,
            Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
        )
        ctx.on_cleanup(lambda r=resource_id: _deregister(aas, r))
        ctx.on_cleanup(lambda r=resource_id: _sweep_alarms(cw, r))

    # ---- Leg 1: the control measures what a policy with the flag ABSENT is provisioned with.
    _put_policy(aas, control_id, control_policy, disable_scale_in=None)
    ctx.on_cleanup(lambda: _delete_policy(aas, control_id, control_policy))
    default_alarms = _poll_until(
        lambda: _alarms_by_kind(cw, control_id), bool, timeout_s=_ALARM_SETTLE_S, interval_s=3.0,
        description=f'the control policy {control_policy!r} provisioning its alarms in '
                    f'CloudWatch, read back by AlarmNamePrefix')
    default_kinds = set(default_alarms)
    assert len(default_kinds) >= 2, (
        f'the control policy provisioned only {sorted(default_kinds)!r} in CloudWatch; this '
        f'check needs a control set containing both a scale-out and a scale-in trigger before '
        f'it can measure what DisableScaleIn removes'
    )
    utilisation = _utilisation_metric(default_alarms)
    scale_in_kind = _scale_in_kind(default_alarms, utilisation)

    # ---- Leg 2: the subject, identical except for the flag, must be missing that trigger.
    _put_policy(aas, subject_id, subject_policy, disable_scale_in=True)
    ctx.on_cleanup(lambda: _delete_policy(aas, subject_id, subject_policy))
    disabled_kinds = set(_poll_until(
        lambda: _alarms_by_kind(cw, subject_id), bool, timeout_s=_ALARM_SETTLE_S, interval_s=3.0,
        description=f'the DisableScaleIn policy {subject_policy!r} provisioning its alarms in '
                    f'CloudWatch'))
    disabled_echo = _stored_config(aas, subject_id, subject_policy).get('DisableScaleIn')
    assert disabled_echo is True, (
        f'DescribeScalingPolicies reports DisableScaleIn={disabled_echo!r} for '
        f'{subject_policy!r}; the flag was set to True and must round-trip before its effect can '
        f'be attributed to it'
    )
    assert scale_in_kind not in disabled_kinds, (
        f'the DisableScaleIn=True policy still provisioned the scale-in trigger '
        f'{scale_in_kind!r} in CloudWatch (kinds {sorted(disabled_kinds)!r}); a policy that '
        f'cannot remove capacity must not be wired to an alarm asking it to'
    )
    assert disabled_kinds < default_kinds, (
        f'DisableScaleIn=True provisioned {sorted(disabled_kinds)!r}, which is not a strict '
        f'subset of the {sorted(default_kinds)!r} the same policy gets with the flag absent; the '
        f'flag must WITHHOLD alarms, not add or replace them'
    )
    withheld = default_kinds - disabled_kinds

    # ---- Leg 3: the flag is not write-once. Flipping it False must MINT the withheld kinds.
    _put_policy(aas, subject_id, subject_policy, disable_scale_in=False)
    enabled_kinds = set(_poll_until(
        lambda: _alarms_by_kind(cw, subject_id),
        lambda found: set(found) == default_kinds, timeout_s=_ALARM_SETTLE_S, interval_s=3.0,
        description=f'the upsert to DisableScaleIn=False minting the withheld kinds '
                    f'{sorted(withheld)!r} for {subject_id!r}'))
    assert enabled_kinds == default_kinds, (
        f'after upserting {subject_policy!r} to DisableScaleIn=False the target is provisioned '
        f'with {sorted(enabled_kinds)!r}, expected the same {sorted(default_kinds)!r} the '
        f'control has -- the flag must be reversible in place'
    )
    enabled_echo = _stored_config(aas, subject_id, subject_policy).get('DisableScaleIn')
    assert enabled_echo is False, (
        f'the upsert to DisableScaleIn=False round-tripped as {enabled_echo!r} on '
        f'DescribeScalingPolicies, expected False'
    )

    # ---- Leg 4: and flipping it back must remove exactly the same kinds again.
    _put_policy(aas, subject_id, subject_policy, disable_scale_in=True)
    redisabled_kinds = set(_poll_until(
        lambda: _alarms_by_kind(cw, subject_id),
        lambda found: set(found) == disabled_kinds, timeout_s=_ALARM_SETTLE_S, interval_s=3.0,
        description=f'the upsert back to DisableScaleIn=True removing {sorted(withheld)!r} again '
                    f'for {subject_id!r}'))
    assert redisabled_kinds == disabled_kinds, (
        f're-disabling scale in left {sorted(redisabled_kinds)!r} provisioned, expected the same '
        f'{sorted(disabled_kinds)!r} as the first time; the transition is not symmetric'
    )

    # The control was never touched, so its inventory must be exactly unchanged -- this is what
    # separates "the flag withheld an alarm" from "something deleted alarms in this account".
    control_now = set(_alarms_by_kind(cw, control_id))
    assert control_now == default_kinds, (
        f'the untouched control target {control_id!r} now has {sorted(control_now)!r} '
        f'provisioned, not the {sorted(default_kinds)!r} it started with; the alarm changes '
        f'cannot be attributed to DisableScaleIn'
    )
    for kind, alarm in _alarms_by_kind(cw, subject_id).items():
        assert alarm['Namespace'] == 'AWS/DynamoDB', (
            f'{kind} on the subject watches namespace {alarm["Namespace"]!r} in region '
            f'{ctx.region} of account {account}, expected "AWS/DynamoDB"'
        )


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
