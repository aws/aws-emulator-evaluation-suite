"""service-linked-role-is-the-role-the-scalable-target-uses."""
from __future__ import annotations

import json
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-linked-role-is-the-role-the-scalable-target-uses"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_START_CAPACITY = 1
_RAISED_FLOOR = 3
_SLR_NAME = 'AWSServiceRoleForApplicationAutoScaling_DynamoDBTable'
_SLR_PRINCIPAL = 'dynamodb.application-autoscaling.amazonaws.com'
_SLR_POLICY = 'AWSApplicationAutoscalingDynamoDBTablePolicy'


def _poll_until(probe, predicate, *, timeout_s, interval_s=4.0, description='condition'):
    """Bounded retry with a deadline that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(
        f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


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


def _policy_document(raw):
    """IAM policy documents come back either JSON-decoded or URL-encoded; accept both."""
    if isinstance(raw, dict):
        return raw
    assert isinstance(raw, str), (
        f'AssumeRolePolicyDocument came back as {type(raw).__name__}, expected a dict or a '
        f'URL-encoded JSON string'
    )
    return json.loads(urllib.parse.unquote(raw))


def _attached_policy_names(iam, role_name):
    names = []
    marker = None
    while True:
        kwargs = {'RoleName': role_name}
        if marker:
            kwargs['Marker'] = marker
        page = iam.list_attached_role_policies(**kwargs)
        names.extend(p['PolicyName'] for p in page['AttachedPolicies'])
        if not page.get('IsTruncated'):
            return names
        marker = page.get('Marker')


def _read_capacity(ddb, table):
    return ddb.describe_table(TableName=table)['Table'][
        'ProvisionedThroughput']['ReadCapacityUnits']


@tags('axis:happy-path', 'cap:c1', 'concern:negative-classes', 'concern:representation',
      'plane:control')
def run(ctx) -> None:
    """A DynamoDB scalable target's RoleARN is exactly IAM's service-linked role: right path, single
    trust principal, documented managed policy, DeleteRole refused, and scaling goes through it.

    Reference: https://docs.aws.amazon.com/autoscaling/application/userguide/services-that-can-integrate-dynamodb.html
    """
    ddb = ctx.client('dynamodb')
    aas = ctx.client('application-autoscaling')
    iam = ctx.client('iam')
    account = ctx.client('sts').get_caller_identity()['Account']

    table = ctx.unique_name('sim2real-behav-aas-slr-')
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

    # Registering a DynamoDB resource is what causes the service-linked role to exist. On a
    # re-run against an account that already has it this is a no-op, which is why nothing below
    # asserts creation -- only identity and use.
    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_START_CAPACITY, MaxCapacity=10,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    target = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'][0]
    reported_arn = target['RoleARN']

    # ---- Leg 1: the reported ARN names a role IAM actually has, and the two agree EXACTLY.
    role = iam.get_role(RoleName=_SLR_NAME)['Role']
    assert role['Arn'] == reported_arn, (
        f'the scalable target reports RoleARN {reported_arn!r} but IAM\'s GetRole for '
        f'{_SLR_NAME!r} reports {role["Arn"]!r}; a substring match is not enough here -- the two '
        f'must be the same role'
    )
    expected_arn = (f'arn:{_partition(reported_arn)}:iam::{account}:role/aws-service-role/'
                    f'{_SLR_PRINCIPAL}/{_SLR_NAME}')
    assert reported_arn == expected_arn, (
        f'the RoleARN is {reported_arn!r}; a DynamoDB scalable target in account {account} is '
        f'backed by {expected_arn!r}'
    )
    assert role['Path'] == f'/aws-service-role/{_SLR_PRINCIPAL}/', (
        f'the role sits at path {role["Path"]!r}; a service-linked role lives at '
        f'"/aws-service-role/{_SLR_PRINCIPAL}/", and a role anywhere else is an ordinary role '
        f'wearing the name'
    )

    # ---- Leg 2: the trust document names exactly the one principal, and nothing else.
    trust = _policy_document(role['AssumeRolePolicyDocument'])
    statements = trust['Statement']
    assert len(statements) == 1, (
        f'the trust document carries {len(statements)} statements {statements!r}; the '
        f'service-linked role trusts exactly one principal for exactly one action'
    )
    statement = statements[0]
    assert statement['Effect'] == 'Allow', (
        f'the trust statement Effect is {statement["Effect"]!r}, expected "Allow"'
    )
    principal = statement['Principal']
    service = principal['Service']
    services = [service] if isinstance(service, str) else sorted(service)
    assert services == [_SLR_PRINCIPAL], (
        f'the trust document allows {services!r} to assume the role; only {_SLR_PRINCIPAL!r} may, '
        f'and a wider trust would let anything change this account\'s DynamoDB capacity'
    )
    action = statement['Action']
    actions = [action] if isinstance(action, str) else sorted(action)
    assert actions == ['sts:AssumeRole'], (
        f'the trust document grants {actions!r}, expected exactly ["sts:AssumeRole"]'
    )

    # ---- Leg 3: the permissions are attached, by the documented name.
    attached = _attached_policy_names(iam, _SLR_NAME)
    assert _SLR_POLICY in attached, (
        f'the service-linked role carries attached managed policies {sorted(attached)!r}; AWS '
        f'documents {_SLR_POLICY!r} as the policy that lets Application Auto Scaling manage '
        f'provisioned table capacity and create CloudWatch alarms, and without it the role cannot '
        f'do the job the target claims it does'
    )

    # ---- Leg 4: the role is unmodifiable through the ordinary IAM path. Positive control first:
    # these credentials can see the role, so a refusal below is about the role, not about access.
    assert iam.get_role(RoleName=_SLR_NAME)['Role']['RoleId'] == role['RoleId'], (
        'the positive control failed: a second GetRole for the same service-linked role returned '
        'a different RoleId, so nothing can be concluded from the refusal below'
    )
    error = _client_error(lambda: iam.delete_role(RoleName=_SLR_NAME))
    assert error.get('Code') == 'UnmodifiableEntity', (
        f'DeleteRole on the service-linked role {_SLR_NAME!r} was refused with '
        f'{error.get("Code")!r}, expected "UnmodifiableEntity" -- a service-linked role is only '
        f'removable through DeleteServiceLinkedRole, which this check deliberately never calls'
    )
    expected = (f"Cannot perform the operation on the protected role '{_SLR_NAME}' - "
                f"this role is only modifiable by AWS")
    assert error.get('Message') == expected, (
        f'DeleteRole refusal message {error.get("Message")!r}, expected {expected!r}'
    )
    survivor = iam.get_role(RoleName=_SLR_NAME)['Role']
    assert survivor['Arn'] == reported_arn, (
        f'after the refused DeleteRole, IAM reports the role as {survivor["Arn"]!r} instead of '
        f'{reported_arn!r}; a refused call must leave the role exactly as it was'
    )
    assert _SLR_POLICY in _attached_policy_names(iam, _SLR_NAME), (
        f'the refused DeleteRole detached {_SLR_POLICY!r} from the service-linked role'
    )

    # ---- Leg 5: and the role is the one the scaling actually goes through. Raising MinCapacity
    # above the live capacity makes Application Auto Scaling call DynamoDB on this account's
    # behalf; if the role were decorative, this is the leg that fails.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_RAISED_FLOOR,
                                 MaxCapacity=10)
    activity = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 1 and _terminal(acts[0]), timeout_s=150, interval_s=4.0,
        description=f'the floor raise to {_RAISED_FLOOR} reaching DynamoDB through the '
                    f'service-linked role')[0]
    assert activity['StatusCode'] == 'Successful', (
        f'the scaling activity ended {activity["StatusCode"]!r} with status message '
        f'{activity.get("StatusMessage")!r}; a role that cannot call DynamoDB produces a failed '
        f'or unfulfilled activity, which is exactly the inverse of the claim here'
    )
    assert activity['Cause'] == f'minimum capacity was set to {_RAISED_FLOOR}', (
        f'the activity attributes itself to {activity["Cause"]!r}, expected '
        f'"minimum capacity was set to {_RAISED_FLOOR}"'
    )
    assert activity['StatusMessage'] == (
        f'Successfully set read capacity units to {_RAISED_FLOOR}. Change successfully fulfilled '
        f'by dynamodb.'
    ), (
        f'the activity status message was {activity["StatusMessage"]!r}; real AWS records that '
        f'dynamodb fulfilled the change, which is the observable proof the role was assumed'
    )
    final = _poll_until(lambda: _read_capacity(ddb, table),
                        lambda cap: cap == _RAISED_FLOOR, timeout_s=90, interval_s=3.0,
                        description=f'DynamoDB provisioned read capacity for {table!r} in region '
                                    f'{ctx.region} reaching the new floor of {_RAISED_FLOOR}')
    assert final == _RAISED_FLOOR, (
        f'table {table!r} is at {final} read capacity units; the floor of {_RAISED_FLOOR} had to '
        f'reach DynamoDB through {reported_arn!r} for that role to be more than a string'
    )


def _partition(arn):
    """The partition out of an ARN, so no partition literal is hardcoded."""
    parts = arn.split(':')
    assert len(parts) > 2 and parts[0] == 'arn', (
        f'{arn!r} is not an ARN, so no partition can be read out of it'
    )
    return parts[1]


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
