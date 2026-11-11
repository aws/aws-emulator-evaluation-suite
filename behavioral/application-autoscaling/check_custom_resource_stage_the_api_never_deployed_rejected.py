"""custom-resource-stage-the-api-never-deployed-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-stage-the-api-never-deployed-rejected"
GROUP = 'scalable-targets'
SERVICES = ['application-autoscaling']

_NS = 'custom-resource'
_DIM = 'custom-resource:ResourceType:Property'


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


def _bounds(aas, resource_id):
    found = []
    for page in aas.get_paginator('describe_scalable_targets').paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_DIM):
        found.extend((t['MinCapacity'], t['MaxCapacity']) for t in page['ScalableTargets'])
    assert len(found) <= 1, f'{len(found)} targets share one resource id'
    return found[0] if found else None


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'plane:control')
def run(ctx) -> None:
    """RegisterScalableTarget on a never-deployed stage of the API is refused ValidationException
    naming the missing execute-api GET/PATCH permissions, registers nothing and leaves the endpoint
    unchanged, while the deployed stage of the same API registers.
    """
    aas = ctx.client('application-autoscaling')
    api_id, resource_id, state = _custom_resource(ctx, desired=2)
    unserved = f"{ctx.api_url(api_id, 'undeployed')}/scalableTargetDimensions/{_DIMENSION_ID}"
    assert unserved != resource_id, 'the undeployed stage resolves to the deployed stage'
    for rid in (unserved, resource_id):
        ctx.on_cleanup(lambda rid=rid: _deregister(aas, rid, _DIM))

    _register_when_reachable(aas, ServiceNamespace=_NS, ResourceId=resource_id,
                             ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=4)
    assert _bounds(aas, resource_id) == (1, 4), (
        f'the deployed stage registered with bounds {_bounds(aas, resource_id)!r}, expected (1, 4)')
    _deregister(aas, resource_id, _DIM)

    code, message = _error(lambda: aas.register_scalable_target(
        ServiceNamespace=_NS, ResourceId=unserved, ScalableDimension=_DIM,
        MinCapacity=3, MaxCapacity=4))
    assert code == 'ValidationException', f'an undeployed stage was refused with {code!r}'
    expected = ('User is missing the following permissions: execute-api:Invoke:PATCH, '
                'execute-api:Invoke:GET')
    assert message == expected, f'refusal message {message!r}, expected {expected!r}'
    assert _bounds(aas, unserved) is None, 'the undeployed stage is registered anyway'
    assert state()[0] == 2.0, (
        f'the endpoint moved to {state()[0]} although its registration was refused')


# The custom resource is the documented Application Auto Scaling contract served by an API
# Gateway REST API (AWS_IAM auth) whose two methods integrate straight with a DynamoDB item:
# GET /scalableTargetDimensions/{id} reads it, PATCH writes desiredCapacity and counts the call.
# No Lambda, so no log group outlives the check.
_DIMENSION_ID = 'sim2real-dim'
_STAGE = 'prod'
_ROLE_PROPAGATION_S = 120.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description='condition'):
    """Poll until predicate holds; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _ignore_missing(fn, *codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response['Error']['Code'] not in codes:
            raise


# A PATCH with a negative desiredCapacity is a no-op for this resource: it is counted and its
# body recorded, but the capacity is kept. A non-negative one sets the capacity.
_PATCH_TEMPLATE = (
    "#set($d = $input.path('$.desiredCapacity'))\n"
    '{"TableName": "@TABLE@", "Key": @KEY@, '
    '#if($d < 0)'
    '"UpdateExpression": "SET lastBody = :b ADD patches :one", '
    '"ExpressionAttributeValues": {":b": {"S": "$util.escapeJavaScript($input.body)"}, '
    '":one": {"N": "1"}}, '
    '#else'
    '"UpdateExpression": "SET desired = :d, lastBody = :b ADD patches :one", '
    '"ExpressionAttributeValues": {":d": {"N": "$d"}, '
    '":b": {"S": "$util.escapeJavaScript($input.body)"}, ":one": {"N": "1"}}, '
    '#end'
    '"ReturnValues": "ALL_NEW"}'
)


def _response_template(root):
    return (
        f"#set($i = $input.path('$.{root}'))\n"
        '{"actualCapacity": $i.desired.N, "desiredCapacity": $i.desired.N, '
        '"dimensionName": "Workers", "resourceName": "sim2real-fleet", '
        '"scalableTargetDimensionId": "$i.id.S", "scalingStatus": "Successful", '
        '"version": "1"}'
    )


def _custom_resource(ctx, *, desired):
    """A custom-resource endpoint at ``desired`` capacity.

    Returns (api_id, resource_id, state_reader).

    ``state_reader()`` returns (desired, patches, last PATCH body) from the backing item.
    """
    iam = ctx.client('iam')
    ddb = ctx.client('dynamodb')
    apigw = ctx.client('apigateway')
    partition = ctx.client('sts').get_caller_identity()['Arn'].split(':')[1]

    table = ctx.unique_name('sim2real-behav-aas-cr-')
    ddb.create_table(
        TableName=table, BillingMode='PAY_PER_REQUEST',
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    _poll_until(lambda: ddb.describe_table(TableName=table)['Table']['TableStatus'],
                lambda s: s == 'ACTIVE', timeout_s=120, interval_s=2.0,
                description=f'table {table!r} becoming ACTIVE')
    ddb.put_item(TableName=table, Item={'id': {'S': _DIMENSION_ID},
                                        'desired': {'N': str(desired)}, 'patches': {'N': '0'}})
    table_arn = f'arn:{partition}:dynamodb:{ctx.region}:{ctx.account}:table/{table}'

    role = ctx.unique_name('sim2real-behav-aas-cr-')
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'apigateway.amazonaws.com'},
                           'Action': 'sts:AssumeRole'}]}),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: _ignore_missing(lambda: iam.delete_role(RoleName=role),
                                           'NoSuchEntity'))
    iam.put_role_policy(RoleName=role, PolicyName='item', PolicyDocument=json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Action': ['dynamodb:GetItem', 'dynamodb:UpdateItem'],
                       'Resource': table_arn}]}))
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName='item'), 'NoSuchEntity'))

    api_id = apigw.create_rest_api(name=ctx.unique_name('sim2real-behav-aas-cr-'),
                                   endpointConfiguration={'types': ['REGIONAL']},
                                   tags={'sim2real': CHECK})['id']
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    root = [r['id'] for r in apigw.get_resources(restApiId=api_id)['items'] if r['path'] == '/'][0]
    parent = apigw.create_resource(restApiId=api_id, parentId=root,
                                   pathPart='scalableTargetDimensions')['id']
    leaf = apigw.create_resource(restApiId=api_id, parentId=parent,
                                 pathPart='{scalableTargetDimensionId}')['id']
    key = "{\"id\": {\"S\": \"$util.escapeJavaScript($input.params('scalableTargetDimensionId'))\"}}"
    requests = {
        'GET': ('GetItem', f'{{"TableName": "{table}", "Key": {key}, "ConsistentRead": true}}',
                'Item'),
        'PATCH': ('UpdateItem', _PATCH_TEMPLATE.replace('@TABLE@', table).replace('@KEY@', key),
                  'Attributes'),
    }
    for method, (action, request, root_key) in requests.items():
        apigw.put_method(restApiId=api_id, resourceId=leaf, httpMethod=method,
                         authorizationType='AWS_IAM',
                         requestParameters={'method.request.path.scalableTargetDimensionId': True})
        apigw.put_integration(
            restApiId=api_id, resourceId=leaf, httpMethod=method, type='AWS',
            integrationHttpMethod='POST',
            uri=f'arn:{partition}:apigateway:{ctx.region}:dynamodb:action/{action}',
            credentials=role_arn, passthroughBehavior='NEVER',
            requestTemplates={'application/json': request})
        apigw.put_method_response(restApiId=api_id, resourceId=leaf, httpMethod=method,
                                  statusCode='200', responseModels={'application/json': 'Empty'})
        apigw.put_integration_response(
            restApiId=api_id, resourceId=leaf, httpMethod=method, statusCode='200',
            responseTemplates={'application/json': _response_template(root_key)})
    apigw.create_deployment(restApiId=api_id, stageName=_STAGE)
    resource_id = f'{ctx.api_url(api_id, _STAGE)}/scalableTargetDimensions/{_DIMENSION_ID}'

    def state():
        item = ddb.get_item(TableName=table, Key={'id': {'S': _DIMENSION_ID}},
                            ConsistentRead=True)['Item']
        body = item.get('lastBody', {}).get('S')
        return float(item['desired']['N']), int(item['patches']['N']), body

    return api_id, resource_id, state


def _register_when_reachable(aas, **kwargs):
    """RegisterScalableTarget, retried while the fresh API stage and its role propagate."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    while True:
        try:
            return aas.register_scalable_target(**kwargs)
        except ClientError as exc:
            if (exc.response['Error']['Code'] != 'ValidationException'
                    or time.monotonic() > deadline):
                raise
            time.sleep(5)


def _delete_table(ddb, name):
    _ignore_missing(lambda: ddb.delete_table(TableName=name), 'ResourceNotFoundException')


def _delete_rest_api(apigw, api_id):
    """DeleteRestApi is rate-limited per account; retry the throttle within a bounded window."""
    deadline = time.monotonic() + 45
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'NotFoundException':
                return
            if code != 'TooManyRequestsException' or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _deregister(aas, resource_id, dimension):
    _ignore_missing(lambda: aas.deregister_scalable_target(
        ServiceNamespace=_NS, ResourceId=resource_id, ScalableDimension=dimension),
        'ObjectNotFoundException')


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


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
