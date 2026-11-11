"""rate-action-stops-firing-after-its-end-time."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rate-action-stops-firing-after-its-end-time"
GROUP = 'scheduled-actions'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_END_LEAD_S = 95
_BARRIER_MARGIN = datetime.timedelta(seconds=70)
_BARRIER_TIMEOUT_S = 330
_CLOCK_SLACK = datetime.timedelta(seconds=2)


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


def _create_table(ddb, name, read_capacity):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PROVISIONED',
        ProvisionedThroughput={'ReadCapacityUnits': read_capacity, 'WriteCapacityUnits': 1},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )


def _wait_active(ddb, name):
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {name!r} becoming ACTIVE')


def _delete_table(ddb, name):
    deadline = time.monotonic() + 40
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _deregister(aas, resource_id, dimension=_DIM):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=dimension)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _activities(aas, resource_id):
    out, token = [], None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _triggers(activities, action):
    cause = f'scheduled action name {action} was triggered'
    return [a for a in activities if a['Cause'] == cause]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scheduled-scaling.html
@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:negative-classes',
      'concern:representation', 'plane:control', 'timing:real-time')
def run(ctx) -> None:
    """A rate() scheduled action with an EndTime stops firing once EndTime passes, while an
    identical action without one, created in the same second on a twin target, keeps firing.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    subject_table = ctx.unique_name('sim2real-behav-aas-rend-')
    control_table = ctx.unique_name('sim2real-behav-aas-rctl-')
    subject_id = f'table/{subject_table}'
    control_id = f'table/{control_table}'
    subject_action = ctx.unique_name('sim2real-behav-aas-rend-sa-')
    control_action = ctx.unique_name('sim2real-behav-aas-rctl-sa-')

    for name in (subject_table, control_table):
        _create_table(ddb, name, 1)
        ctx.on_cleanup(lambda n=name: _delete_table(ddb, n))
    for name in (subject_table, control_table):
        _wait_active(ddb, name)
    for resource_id in (subject_id, control_id):
        aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                     ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=20)
        ctx.on_cleanup(lambda r=resource_id: _deregister(aas, r))

    end = (datetime.datetime.now(datetime.timezone.utc)
           + datetime.timedelta(seconds=_END_LEAD_S)).replace(microsecond=0)
    # Deregistering a target deletes its scheduled actions, so the target cleanups cover both.
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=subject_id, ScalableDimension=_DIM,
        ScheduledActionName=subject_action, Schedule='rate(1 minute)', EndTime=end,
        ScalableTargetAction={'MinCapacity': 2},
    )
    aas.put_scheduled_action(
        ServiceNamespace=_NS, ResourceId=control_id, ScalableDimension=_DIM,
        ScheduledActionName=control_action, Schedule='rate(1 minute)',
        ScalableTargetAction={'MinCapacity': 2},
    )

    barrier = end + _BARRIER_MARGIN
    _poll_until(
        lambda: _triggers(_activities(aas, control_id), control_action),
        lambda acts: any(a['StartTime'] > barrier for a in acts),
        timeout_s=_BARRIER_TIMEOUT_S, interval_s=5.0,
        description=f'the control rate action firing after {barrier.isoformat()} '
                    f'(EndTime {end.isoformat()} plus a full interval)')

    fired = _triggers(_activities(aas, subject_id), subject_action)
    assert fired, (
        f'the subject rate action never fired at all, although its EndTime {end.isoformat()} '
        f'left at least one interval open')
    late = sorted(a['StartTime'].isoformat() for a in fired if a['StartTime'] > end + _CLOCK_SLACK)
    assert not late, (
        f'the subject rate action fired at {late!r}, after its EndTime {end.isoformat()}; '
        f'the control kept firing past {barrier.isoformat()}, so the recurrence did not end')
    assert all(a['StatusCode'] == 'Successful' for a in fired), (
        f'subject firings ended {[a["StatusCode"] for a in fired]!r}, expected all Successful')

    stored = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=subject_id,
                                            ScheduledActionNames=[subject_action])
    stored = stored['ScheduledActions']
    assert len(stored) == 1 and stored[0].get('EndTime') == end, (
        f'after EndTime the action should still be listed with EndTime {end.isoformat()}, but '
        f'DescribeScheduledActions returned {stored!r}')
    _poll_until(
        lambda: ddb.describe_table(TableName=subject_table)['Table'],
        lambda t: t['TableStatus'] == 'ACTIVE' and t['ProvisionedThroughput']['ReadCapacityUnits'] == 2,
        timeout_s=120, interval_s=5.0,
        description='the subject table ACTIVE at the read capacity 2 its firings set')
    _poll_until(
        lambda: ddb.describe_table(TableName=control_table)['Table']['TableStatus'],
        lambda s: s == 'ACTIVE', timeout_s=120, interval_s=5.0,
        description='the control table settling ACTIVE')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
