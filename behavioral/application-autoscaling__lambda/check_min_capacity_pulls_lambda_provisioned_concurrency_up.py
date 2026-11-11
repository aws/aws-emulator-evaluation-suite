"""min-capacity-pulls-lambda-provisioned-concurrency-up."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "min-capacity-pulls-lambda-provisioned-concurrency-up"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling', 'lambda']

_NS = 'lambda'
_DIM = 'lambda:function:ProvisionedConcurrency'
_ALIAS = 'BLUE'
_FLOOR = 2
_CEILING = 10
_LOWERED_CEILING = 1
_RESERVE_HEADROOM = 100  # Lambda keeps 100 concurrent executions unreserved
_IAM_PROPAGATION_S = 90.0
_ALLOCATE_S = 210.0
_SLR_NAME = 'AWSServiceRoleForApplicationAutoScaling_LambdaConcurrency'
_SLR_PRINCIPAL = 'lambda.application-autoscaling.amazonaws.com'
# Prefixed with the caller's partition at run time.
_BASIC_EXECUTION_SUFFIX = 'iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
_SOURCE = 'def handler(event, context):\n    return {"ok": True}\n'


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


def _zip_source():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('index.py', _SOURCE)
    return buf.getvalue()


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ObjectNotFoundException':
            raise


def _drop_provisioned(lam, function_name):
    try:
        lam.delete_provisioned_concurrency_config(FunctionName=function_name, Qualifier=_ALIAS)
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        if code != 'ResourceNotFoundException':
            raise RuntimeError(f'provisioned concurrency for {function_name}:{_ALIAS} not deleted, and '
                               f'it is BILLED while it survives: {code}') from exc


def _drop_function(lam, logs, function_name):
    try:
        lam.delete_function(FunctionName=function_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise
    try:
        logs.delete_log_group(logGroupName=f'/aws/lambda/{function_name}')
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


def _drop_role(iam, role_name, basic_execution):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_execution)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NoSuchEntity':
            raise


def _activities(aas, resource_id):
    out = []
    token = None
    while True:
        kwargs = {'ServiceNamespace': _NS, 'ResourceId': resource_id, 'ScalableDimension': _DIM,
                  'IncludeNotScaledActivities': True}
        if token:
            kwargs['NextToken'] = token
        page = aas.describe_scaling_activities(**kwargs)
        out.extend(page['ScalingActivities'])
        token = page.get('NextToken')
        if not token:
            return out


def _terminal(activity):
    return activity['StatusCode'] in ('Successful', 'Failed', 'Overridden', 'Unfulfilled')


def _provisioned(lam, function_name):
    """Lambda's own provisioned concurrency config for the alias, or None while none exists."""
    try:
        return lam.get_provisioned_concurrency_config(FunctionName=function_name,
                                                      Qualifier=_ALIAS)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'ProvisionedConcurrencyConfigNotFoundException':
            return None
        raise


@tags('axis:happy-path', 'cap:c1', 'cap:c4', 'concern:representation', 'plane:control')
def run(ctx) -> None:
    """Registering a Lambda alias with MinCapacity above its provisioned concurrency makes Application
    Auto Scaling raise it with no scaling policy, and a lower MaxCapacity pushes it back down,
    as Lambda reports, under the Lambda-specific service-linked role."""
    aas = ctx.client('application-autoscaling')
    iam = ctx.client('iam')
    lam = ctx.client('lambda')
    logs = ctx.client('logs')
    caller = ctx.client('sts').get_caller_identity()
    account = caller['Account']
    partition = _partition(caller['Arn'])
    basic_execution = f'arn:{partition}:{_BASIC_EXECUTION_SUFFIX}'

    # The concurrency limit varies by account, so it is read, never assumed.
    settings = lam.get_account_settings()
    unreserved = settings['AccountLimit']['UnreservedConcurrentExecutions']
    assert unreserved >= _FLOOR + _RESERVE_HEADROOM, (
        f'this account reports {unreserved} unreserved concurrent executions out of a limit of '
        f'{settings["AccountLimit"]["ConcurrentExecutions"]}; Lambda requires '
        f'{_RESERVE_HEADROOM} to remain unreserved, so provisioning {_FLOOR} needs at least '
        f'{_FLOOR + _RESERVE_HEADROOM} and this check cannot demonstrate anything here'
    )

    role_name = ctx.unique_name('sim2real-aas-lam-')
    function_name = ctx.unique_name('sim2real-behav-aas-pc-')
    resource_id = f'function:{function_name}:{_ALIAS}'

    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow',
                           'Principal': {'Service': 'lambda.amazonaws.com'},
                           'Action': 'sts:AssumeRole'}],
        }),
        Tags=[{'Key': 'sim2real', 'Value': CHECK},
              {'Key': 'owner', 'Value': 'sim2real-behav-aas'}],
    )['Role']['Arn']
    ctx.on_cleanup(lambda: _drop_role(iam, role_name, basic_execution))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_execution)

    # IAM propagation: CreateFunction refuses a role Lambda cannot yet assume.
    deadline = time.monotonic() + _IAM_PROPAGATION_S
    last_error = None
    created = None
    while time.monotonic() < deadline:
        try:
            created = lam.create_function(
                FunctionName=function_name,
                Runtime='python3.12',
                Role=role_arn,
                Handler='index.handler',
                Code={'ZipFile': _zip_source()},
                Timeout=10,
                Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
            )
            break
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') != 'InvalidParameterValueException':
                raise
            last_error = exc.response.get('Error', {}).get('Message')
            time.sleep(5.0)
    assert created is not None, (
        f'CreateFunction never accepted the freshly created role {role_arn!r} within '
        f'{_IAM_PROPAGATION_S}s of IAM propagation retries; last message was {last_error!r}'
    )
    ctx.on_cleanup(lambda: _drop_function(lam, logs, function_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)['State'],
        lambda state: state == 'Active', timeout_s=90, interval_s=3.0,
        description=f'function {function_name!r} reaching State Active -- a version cannot be '
                    f'published until it does')

    version = lam.publish_version(FunctionName=function_name)['Version']
    lam.create_alias(FunctionName=function_name, Name=_ALIAS, FunctionVersion=version)
    assert _provisioned(lam, function_name) is None, (
        f'the alias {function_name}:{_ALIAS} already has a provisioned concurrency config before '
        f'anything registered it as a scalable target; this check must start from nothing so the '
        f'allocation is attributable to Application Auto Scaling'
    )

    # ---- Leg 1: register a floor ABOVE the live capacity, with no scaling policy anywhere.
    aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=_DIM,
        MinCapacity=_FLOOR, MaxCapacity=_CEILING,
        Tags={'sim2real': CHECK, 'owner': 'sim2real-behav-aas'},
    )
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    ctx.on_cleanup(lambda: _drop_provisioned(lam, function_name))

    target = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[resource_id])['ScalableTargets'][0]
    assert (target['MinCapacity'], target['MaxCapacity']) == (_FLOOR, _CEILING), (
        f'the registered bounds came back as '
        f'({target["MinCapacity"]}, {target["MaxCapacity"]}), expected ({_FLOOR}, {_CEILING})'
    )
    expected_slr = (f'arn:{partition}:iam::{account}:role/aws-service-role/'
                    f'{_SLR_PRINCIPAL}/{_SLR_NAME}')
    assert target['RoleARN'] == expected_slr, (
        f'the Lambda scalable target reports RoleARN {target["RoleARN"]!r}; a lambda-namespace '
        f'target is backed by the Lambda-specific service-linked role {expected_slr!r}, not the '
        f'DynamoDB one -- reporting a single service-linked role for every namespace is exactly '
        f'the single-namespace bug this check exists to find'
    )
    assert _SLR_NAME in _slr_names(iam, _SLR_PRINCIPAL), (
        f'IAM has no service-linked role named {_SLR_NAME!r} under the '
        f'/aws-service-role/{_SLR_PRINCIPAL}/ path even though a Lambda scalable target claims to '
        f'use it; the roles found there were {_slr_names(iam, _SLR_PRINCIPAL)!r}'
    )

    config = _poll_until(
        lambda: _provisioned(lam, function_name),
        lambda cfg: cfg is not None
        and cfg['Status'] == 'READY'
        and cfg['AllocatedProvisionedConcurrentExecutions'] == _FLOOR,
        timeout_s=_ALLOCATE_S, interval_s=8.0,
        description=f'Lambda allocating {_FLOOR} provisioned concurrent executions for '
                    f'{function_name}:{_ALIAS} because the registered MinCapacity of {_FLOOR} is '
                    f'above the alias\'s live capacity of 0, with no scaling policy involved')
    assert config['RequestedProvisionedConcurrentExecutions'] == _FLOOR, (
        f'Lambda reports {config["RequestedProvisionedConcurrentExecutions"]} requested '
        f'provisioned concurrent executions for {function_name}:{_ALIAS} in region {ctx.region} of '
        f'account {account}; the registered MinCapacity of {_FLOOR} must reach Lambda, not only '
        f'the Application Auto Scaling record'
    )
    assert config['AllocatedProvisionedConcurrentExecutions'] == _FLOOR, (
        f'Lambda allocated {config["AllocatedProvisionedConcurrentExecutions"]} of the '
        f'{_FLOOR} requested; a floor that is requested but never allocated has not moved capacity'
    )
    assert config['AvailableProvisionedConcurrentExecutions'] == _FLOOR, (
        f'Lambda reports {config["AvailableProvisionedConcurrentExecutions"]} available of '
        f'{_FLOOR} allocated with no invocations in flight; the whole pool must be available'
    )

    up = _poll_until(
        lambda: _activities(aas, resource_id),
        lambda acts: len(acts) >= 1 and _terminal(acts[0]), timeout_s=90, interval_s=4.0,
        description=f'the scale-out to the floor being recorded as a terminal scaling activity for '
                    f'{resource_id!r}')[0]
    assert up['StatusCode'] == 'Successful', (
        f'the floor-enforcement activity ended {up["StatusCode"]!r} with status message '
        f'{up.get("StatusMessage")!r}'
    )
    assert up['Cause'] == f'minimum capacity was set to {_FLOOR}', (
        f'the activity attributes itself to {up["Cause"]!r}, expected '
        f'"minimum capacity was set to {_FLOOR}"'
    )
    assert str(_FLOOR) in up['Description'], (
        f'the activity described itself as {up["Description"]!r} without naming the '
        f'{_FLOOR} it set; the exact sentence for the lambda namespace is unmeasured, so this '
        f'asserts only that the number is in it -- tighten to the real sentence after the first '
        f'replay'
    )
    assert _NS in up['StatusMessage'], (
        f'the activity status message was {up["StatusMessage"]!r}; real AWS records which target '
        f'service fulfilled the change and it must name {_NS!r}, not dynamodb'
    )
    assert up['ScalableDimension'] == _DIM, (
        f'the activity carried scalable dimension {up["ScalableDimension"]!r}, expected {_DIM!r}'
    )

    # ---- Leg 2: the other direction. Lowering the ceiling below the live allocation must push
    # Lambda's pool back down, which separates "wrote the floor once" from "enforces the bounds".
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=_LOWERED_CEILING,
                                 MaxCapacity=_LOWERED_CEILING)
    lowered = _poll_until(
        lambda: _provisioned(lam, function_name),
        lambda cfg: cfg is not None
        and cfg['Status'] == 'READY'
        and cfg['AllocatedProvisionedConcurrentExecutions'] == _LOWERED_CEILING,
        timeout_s=_ALLOCATE_S, interval_s=8.0,
        description=f'Lambda reducing provisioned concurrency for {function_name}:{_ALIAS} from '
                    f'{_FLOOR} down to the new MaxCapacity of {_LOWERED_CEILING}')
    assert lowered['RequestedProvisionedConcurrentExecutions'] == _LOWERED_CEILING, (
        f'Lambda still reports {lowered["RequestedProvisionedConcurrentExecutions"]} requested '
        f'provisioned concurrent executions after MaxCapacity was lowered to '
        f'{_LOWERED_CEILING}; a ceiling below the live capacity must scale it in'
    )
    down = _activities(aas, resource_id)[0]
    assert down['Cause'] == f'maximum capacity was set to {_LOWERED_CEILING}', (
        f'the scale-in activity attributes itself to {down["Cause"]!r}, expected '
        f'"maximum capacity was set to {_LOWERED_CEILING}"'
    )
    assert down['ActivityId'] != up['ActivityId'], (
        f'the newest activity is still {up["ActivityId"]!r}; the ceiling decrease must be recorded '
        f'as its own activity'
    )


def _partition(arn):
    """The partition out of an ARN, so no partition literal is hardcoded."""
    parts = arn.split(':')
    assert len(parts) > 2 and parts[0] == 'arn', (
        f'{arn!r} is not an ARN, so no partition can be read out of it'
    )
    return parts[1]


def _slr_names(iam, principal):
    """Every role name under the service-linked path for one principal, straight from IAM."""
    prefix = f'/aws-service-role/{principal}/'
    names = []
    marker = None
    while True:
        kwargs = {'PathPrefix': prefix}
        if marker:
            kwargs['Marker'] = marker
        page = iam.list_roles(**kwargs)
        names.extend(role['RoleName'] for role in page['Roles'])
        if not page.get('IsTruncated'):
            return names
        marker = page.get('Marker')


if __name__ == '__main__':
    from fidelity_tests_runner import main

    main(run)
