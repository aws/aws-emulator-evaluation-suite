"""register-upsert-carrying-tags-rejected-and-bounds-kept."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-upsert-carrying-tags-rejected-and-bounds-kept"
GROUP = 'tagging'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_REJECT = ('The scalable target that you tried to tag already exists. To update tags on an '
           'existing scalable target, use the TagResource API.')


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


def _client_error(fn):
    """The Error dict ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'concern:representation',
      'plane:control')
def run(ctx) -> None:
    """Tags on RegisterScalableTarget are create-only: re-registering an existing target with Tags
    is refused as a whole -- the new MaxCapacity in the same call is NOT applied and the tags are
    unchanged -- while the same upsert without Tags applies, and TagResource then adds the tag.
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    table = ctx.unique_name('sim2real-behav-aas-rtag-')
    resource_id = f'table/{table}'

    _create_table(ddb, table, 1)
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _wait_active(ddb, table)
    arn = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=10, Tags={'team': 'alpha'})['ScalableTargetARN']
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    assert aas.list_tags_for_resource(ResourceARN=arn)['Tags'] == {'team': 'alpha'}, (
        'the create-time tag was not stored on the new scalable target')

    error = _client_error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=7, Tags={'team': 'beta'}))
    assert error['Code'] == 'ValidationException', (
        f'an upsert carrying Tags was refused with {error["Code"]!r}, expected '
        f'"ValidationException"')
    assert error['Message'] == _REJECT, (
        f'the refusal message was {error["Message"]!r}, expected {_REJECT!r}')

    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert target['MaxCapacity'] == 10, (
        f'the refused upsert still moved MaxCapacity to {target["MaxCapacity"]}; it must stay 10')
    assert aas.list_tags_for_resource(ResourceARN=arn)['Tags'] == {'team': 'alpha'}, (
        'the refused upsert changed the tags; they must still be {"team": "alpha"}')

    again = aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=1, MaxCapacity=7)['ScalableTargetARN']
    assert again == arn, 'an upsert without Tags returned a different ScalableTargetARN'
    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets'][0]
    assert target['MaxCapacity'] == 7, (
        f'the upsert without Tags left MaxCapacity at {target["MaxCapacity"]}, expected 7')
    aas.tag_resource(ResourceARN=arn, Tags={'team': 'beta', 'tier': 'gold'})
    assert aas.list_tags_for_resource(ResourceARN=arn)['Tags'] == {'team': 'beta',
                                                                   'tier': 'gold'}, (
        'TagResource did not replace team and add tier on the existing target')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
