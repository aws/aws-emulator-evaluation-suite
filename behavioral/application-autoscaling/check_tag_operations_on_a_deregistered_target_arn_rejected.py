"""tag-operations-on-a-deregistered-target-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-operations-on-a-deregistered-target-arn-rejected"
GROUP = 'tagging'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_PROV = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}



def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description='condition'):
    """Bounded poll that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _client_error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS refuses this call, but it SUCCEEDED and returned {result!r}')


def _create_table(ctx, ddb, name, **extra):
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=extra.pop('AttributeDefinitions',
                                       [{'AttributeName': 'pk', 'AttributeType': 'S'}]),
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
        **extra,
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, name))
    _poll_until(lambda: ddb.describe_table(TableName=name)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=180, description=f'table {name!r} ACTIVE')


def _delete_table(ddb, name):
    """DeleteTable refuses while the table is UPDATING; retry that, bounded, and raise otherwise."""
    deadline = time.monotonic() + 45
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
            time.sleep(5)


def _deregister(aas, ns, resource_id, dim):
    try:
        aas.deregister_scalable_target(ServiceNamespace=ns, ResourceId=resource_id,
                                       ScalableDimension=dim)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ObjectNotFoundException':
            raise


def _targets(aas, ns, resource_id):
    out = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=ns, ResourceIds=[resource_id]):
        out.extend(page['ScalableTargets'])
    return out


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """ListTagsForResource, TagResource and UntagResource succeed on a live target ARN and each fail
    with ResourceNotFoundException once it is deregistered; the refused tag does not revive it."""
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-deadarn-')
    _create_table(ctx, ddb, table, BillingMode='PROVISIONED', ProvisionedThroughput=_PROV)
    resource_id = f'table/{table}'
    arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=5, Tags={'team': 'blue'})['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, _NS, resource_id, _DIM))

    # Positive control: the live ARN serves all three calls.
    aas.tag_resource(ResourceARN=arn, Tags={'env': 'test'})
    aas.untag_resource(ResourceARN=arn, TagKeys=['team'])
    live = aas.list_tags_for_resource(ResourceARN=arn)['Tags']
    assert live == {'env': 'test'}, f'the live target lists {live!r}'

    aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                   ScalableDimension=_DIM)
    calls = {
        'ListTagsForResource': lambda: aas.list_tags_for_resource(ResourceARN=arn),
        'TagResource': lambda: aas.tag_resource(ResourceARN=arn, Tags={'env': 'prod'}),
        'UntagResource': lambda: aas.untag_resource(ResourceARN=arn, TagKeys=['env']),
    }
    for op, call in calls.items():
        error = _client_error(call)
        assert (error.get('Code'), error.get('Message')) == (
            'ResourceNotFoundException', 'Scalable Target not found'), (
            f'{op} on the deregistered target ARN was refused with {error!r}')
    assert _targets(aas, _NS, resource_id) == [], (
        'the refused TagResource re-created the deregistered target')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
