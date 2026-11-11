"""custom-resource-registration-floor-patches-the-endpoint."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-resource-registration-floor-patches-the-endpoint"
GROUP = 'data-plane'
SERVICES = ['application-autoscaling']

_NS = 'custom-resource'
_DIM = 'custom-resource:ResourceType:Property'


@tags('axis:happy-path', 'cap:c1', 'concern:data-plane', 'concern:representation',
      'dp:api', 'plane:data')
def run(ctx) -> None:
    """Registering a custom-resource target with MinCapacity above the endpoint's capacity PATCHes
    the endpoint to {"desiredCapacity": 3.0}, records a Successful activity fulfilled by the custom
    resource, and reads back with the registered bounds and the service-linked role.
    """
    aas = ctx.client('application-autoscaling')
    resource_id, state = _custom_resource(ctx, desired=2)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id, _DIM))

    _register_when_reachable(aas, ServiceNamespace=_NS, ResourceId=resource_id,
                             ScalableDimension=_DIM, MinCapacity=3, MaxCapacity=6)

    desired, _patches, body = _poll_until(state, lambda s: s[0] != 2.0, timeout_s=180,
                                          interval_s=5.0,
                                          description='the endpoint capacity leaving 2')
    assert desired == 3.0, f'the endpoint holds desired={desired}; the floor of 3 is a PATCH to 3'
    assert json.loads(body) == {'desiredCapacity': 3.0}, (
        f'the PATCH that moved the endpoint carried {body!r}, expected {{"desiredCapacity": 3.0}}')
    activities = _poll_until(
        lambda: _activities(aas, resource_id, _DIM),
        lambda acts: acts and all(a['StatusCode'] == 'Successful' for a in acts),
        timeout_s=180, interval_s=5.0, description='the registration activity being Successful')
    shapes = [(a['Cause'], a['Description'], a['StatusMessage']) for a in activities]
    assert shapes == [(
        'minimum capacity was set to 3', 'Setting desired capacity to 3.',
        'Successfully set desired capacity to 3. Change successfully fulfilled by custom-resource.',
    )], f'activities were {shapes!r}'
    target = aas.describe_scalable_targets(ServiceNamespace=_NS, ResourceIds=[resource_id],
                                           ScalableDimension=_DIM)['ScalableTargets']
    assert [(t['MinCapacity'], t['MaxCapacity']) for t in target] == [(3, 6)], (
        f'the target reads back as {[(t["MinCapacity"], t["MaxCapacity"]) for t in target]!r}')
    role = target[0]['RoleARN'].split('/')[-1]
    assert role == 'AWSServiceRoleForApplicationAutoScaling_CustomResource', (
        f'the target signs its calls as {role!r}, expected the custom-resource service-linked role')


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
    """A custom-resource endpoint at ``desired`` capacity; returns (resource_id, state_reader).

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

    return resource_id, state


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
