"""ddb-stream-esm-maximum-record-age-60-discards-aged-records-delivers-fresh."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-maximum-record-age-60-discards-aged-records-delivers-fresh"
GROUP = 'error-propagation'
SERVICES = ['dynamodb', 'lambda']

_AGED = 4                        # versions 0..3, written before the mappings exist
_FRESH = 99                      # written after the mappings exist
_MAX_AGE_S = 60                  # the subject's filter
_AGE_TARGET_S = 70               # the aged records must be demonstrably older than the filter
_AGING_BUDGET_S = 180
_CONTROL_BUDGET_S = 240          # bound for the age=-1 twin to deliver the aged batch AND the fresh record


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A TRIM_HORIZON DynamoDB-stream ESM whose oldest records already exceed
    MaximumRecordAgeInSeconds at creation discards those records and delivers the fresh record
    written after it, while an age=-1 twin delivers the aged batch and the fresh record.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
    """
    ddb = ctx.client('dynamodb')
    streams = ctx.client('dynamodbstreams')
    lam = ctx.client('lambda')

    sink = _create_table(ctx, 'audit')
    ddb.put_item(TableName=sink['name'], Item={'pk': {'S': 'log'}, 'entries': {'L': []}})
    subject = _create_table(ctx, 'src-aged-out', stream=True)
    control = _create_table(ctx, 'src-infinite', stream=True)

    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK_TABLE = os.environ["SINK_TABLE"]

    def handler(event, context):
        records = event["Records"]
        # arn:aws:dynamodb:<region>:<acct>:table/<name>/stream/<label>
        source = records[0]["eventSourceARN"].split(":table/")[1].split("/stream/")[0]
        versions = [
            int(r["dynamodb"]["NewImage"]["v"]["N"])
            for r in records
            if "NewImage" in r["dynamodb"]
        ]
        ddb.update_item(
            TableName=SINK_TABLE,
            Key={"pk": {"S": "log"}},
            UpdateExpression="SET #e = list_append(#e, :v)",
            ExpressionAttributeNames={"#e": "entries"},
            ExpressionAttributeValues={
                ":v": {"L": [{"S": json.dumps({"src": source, "b": versions})}]}
            },
        )
        return {"processed": len(versions)}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {'Action': ['dynamodb:GetRecords', 'dynamodb:GetShardIterator',
                        'dynamodb:DescribeStream', 'dynamodb:ListStreams'],
             'Resource': [f'{subject["arn"]}/stream/*', f'{control["arn"]}/stream/*']},
            {'Action': ['dynamodb:UpdateItem'], 'Resource': sink['arn']},
        ],
        env={'SINK_TABLE': sink['name']},
    )

    # --- the aged records, written to BOTH twins in the same instant, before either mapping exists
    key = {'pk': {'S': 'aging-item'}}
    for table in (subject['name'], control['name']):
        ddb.put_item(TableName=table, Item={**key, 'v': {'N': '0'}})
        for version in range(1, _AGED):
            ddb.update_item(
                TableName=table, Key=key,
                UpdateExpression='SET v = :v',
                ExpressionAttributeValues={':v': {'N': str(version)}},
            )

    # --- age them, measured on the TARGET's clock, not ours ---
    oldest_age = _poll_until(
        lambda: _oldest_record_age_s(streams, subject['stream_arn']),
        lambda age: age is not None and age >= _AGE_TARGET_S,
        timeout_s=_AGING_BUDGET_S, interval_s=3.0,
        description=(
            f'the subject stream\'s oldest record to report an ApproximateCreationDateTime at least '
            f'{_AGE_TARGET_S}s in the past. Until it does, a discard could not be attributed to '
            f'MaximumRecordAgeInSeconds={_MAX_AGE_S} rather than to the mapping simply not having read '
            f'yet -- so the absence asserted below would be worthless'
        ),
    )
    assert oldest_age > _MAX_AGE_S, (
        f'the records must be demonstrably older than the filter before the mappings are attached: '
        f'measured age {oldest_age!r}s against MaximumRecordAgeInSeconds={_MAX_AGE_S!r}'
    )

    # --- one field apart ---
    subject_uuid = _wire_stream_esm(ctx, fn['name'], subject['stream_arn'],
                                    BatchSize=_AGED + 5,
                                    MaximumBatchingWindowInSeconds=0,
                                    MaximumRecordAgeInSeconds=_MAX_AGE_S)
    _wire_stream_esm(ctx, fn['name'], control['stream_arn'],
                     BatchSize=_AGED + 5,
                     MaximumBatchingWindowInSeconds=0,
                     MaximumRecordAgeInSeconds=-1)

    # --- a FRESH record on each twin: the positive control on the subject's own wiring ---
    for table in (subject['name'], control['name']):
        ddb.update_item(
            TableName=table, Key=key,
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={':v': {'N': str(_FRESH)}},
        )

    def _entries():
        item = ddb.get_item(TableName=sink['name'], Key={'pk': {'S': 'log'}},
                            ConsistentRead=True).get('Item')
        return [json.loads(e['S']) for e in item['entries']['L']] if item else []

    def _seen(entries, table_name):
        return {v for e in entries if e['src'] == table_name for v in e['b']}

    def _settled(entries):
        return (set(range(_AGED)) <= _seen(entries, control['name'])
                and _FRESH in _seen(entries, control['name'])
                and _FRESH in _seen(entries, subject['name']))

    # --- both twins deliver the fresh record; only the control delivers the aged ones ---
    entries = _poll_until(
        _entries, _settled,
        timeout_s=_CONTROL_BUDGET_S, interval_s=5.0,
        description=(
            'the infinite-age (-1) mapping to deliver both the AGED records and the FRESH record, '
            'and the aged-out mapping to deliver the FRESH record'
        ),
    )
    control_seen = _seen(entries, control['name'])
    subject_seen = _seen(entries, subject['name'])

    assert control_seen == set(range(_AGED)) | {_FRESH}, (
        f'MaximumRecordAgeInSeconds=-1 is documented as infinite, so the control mapping must '
        f'deliver every aged record and the fresh one: saw {sorted(control_seen)!r}, expected '
        f'{sorted(set(range(_AGED)) | {_FRESH})!r}'
    )

    # --- records older than MaximumRecordAgeInSeconds are discarded and the shard keeps going:
    # the fresh record arrives, none of the aged records ever do (shard order puts them first) ---
    assert subject_seen == {_FRESH}, (
        f'a DynamoDB-stream ESM with MaximumRecordAgeInSeconds={_MAX_AGE_S!r} must discard the '
        f'records already older than that and deliver the fresh one: the aged-out mapping saw '
        f'{sorted(subject_seen)!r}, expected [{_FRESH!r}] (control saw {sorted(control_seen)!r})'
    )

    # --- the mapping stays Enabled and echoes the configured age filter ---
    described = lam.get_event_source_mapping(UUID=subject_uuid)
    assert described['State'] in ('Enabled', 'Updating'), (
        f'the aged-out mapping must still be running after discarding aged records: State {described.get("State")!r}, LastProcessingResult '
        f'{described.get("LastProcessingResult")!r}'
    )
    assert described.get('MaximumRecordAgeInSeconds') == _MAX_AGE_S, (
        f'GetEventSourceMapping must echo the configured MaximumRecordAgeInSeconds '
        f'{_MAX_AGE_S!r}, got {described.get("MaximumRecordAgeInSeconds")!r}'
    )

    # --- and the source tables themselves are untouched by any of this ---
    for table in (subject['name'], control['name']):
        stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
        assert stored == {**key, 'v': {'N': str(_FRESH)}}, (
            f'the age filter is a consumer-side concern and must not affect the table {table!r}; '
            f'GetItem returned {stored!r}, expected v={_FRESH!r}'
        )


_XSVC_PREFIX = 'sim2real-xsvc-'
_MANAGED_TAGS = {'sim2real:managed': 'true', 'sim2real:check': CHECK}


def _tags_kv() -> list[dict[str, str]]:
    return [{'Key': k, 'Value': v} for k, v in _MANAGED_TAGS.items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f'{_XSVC_PREFIX}{kind}-')


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds. RAISES on timeout -- never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not observed within {timeout_s}s; last saw {last!r}')


def _swallow(fn) -> None:
    """Teardown-only: a cleanup step already done must not mask the real verdict."""
    try:
        fn()
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f'teardown step failed: {exc}') from exc


def _oldest_record_age_s(streams, stream_arn):
    """Age in seconds of the oldest readable record on this stream, per the TARGET's clock
    (its ApproximateCreationDateTime), or None while no record is readable yet."""
    described = streams.describe_stream(StreamArn=stream_arn)['StreamDescription']
    oldest = None
    for shard in described.get('Shards', []):
        cursor = streams.get_shard_iterator(
            StreamArn=stream_arn, ShardId=shard['ShardId'],
            ShardIteratorType='TRIM_HORIZON',
        )['ShardIterator']
        for record in streams.get_records(ShardIterator=cursor).get('Records', []):
            created = record['dynamodb']['ApproximateCreationDateTime']
            if not isinstance(created, datetime):
                created = datetime.fromtimestamp(float(created), tz=timezone.utc)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if oldest is None or created < oldest:
                oldest = created
    if oldest is None:
        return None
    return (datetime.now(timezone.utc) - oldest).total_seconds()


def _create_table(ctx, kind, *, stream=False) -> dict[str, str]:
    ddb = ctx.client('dynamodb')
    name = _xname(ctx, kind)
    params: dict[str, Any] = {
        'TableName': name,
        'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
        'BillingMode': 'PAY_PER_REQUEST',
        'Tags': _tags_kv(),
    }
    if stream:
        params['StreamSpecification'] = {'StreamEnabled': True,
                                         'StreamViewType': 'NEW_AND_OLD_IMAGES'}
    resp = ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name,
                                       WaiterConfig={'Delay': 2, 'MaxAttempts': 60})
    out = {'name': name, 'arn': resp['TableDescription']['TableArn']}
    if stream:
        stream_arn = resp['TableDescription'].get('LatestStreamArn')
        assert stream_arn, (
            f'CreateTable with StreamEnabled must mint a LatestStreamArn for {name}, got '
            f'{stream_arn!r}'
        )
        out['stream_arn'] = stream_arn
    return out


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client('iam')
    _swallow(lambda: [
        iam.detach_role_policy(RoleName=role_name, PolicyArn=p['PolicyArn'])
        for p in iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
    ])
    _swallow(lambda: [
        iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        for p in iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
    ])
    _swallow(lambda: iam.delete_role(RoleName=role_name))


def _create_lambda(ctx, handler_code, *, permissions, env) -> dict[str, str]:
    """A Lambda plus an execution role scoped to `permissions`; logs are always allowed. Role
    propagation is absorbed by a bounded create_function retry rather than a sleep."""
    iam = ctx.client('iam')
    lam = ctx.client('lambda')

    statements: list[dict[str, Any]] = [{
        'Effect': 'Allow',
        'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
        'Resource': 'arn:aws:logs:*:*:*',
    }]
    for perm in permissions:
        statements.append({'Effect': 'Allow', 'Action': perm['Action'],
                           'Resource': perm['Resource']})
    role_name = _xname(ctx, 'role')
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow',
                           'Principal': {'Service': 'lambda.amazonaws.com'},
                           'Action': 'sts:AssumeRole'}],
        }),
        Path='/sim2real/',
        Tags=_tags_kv(),
    )['Role']['Arn']
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName='inline',
                        PolicyDocument=json.dumps({'Version': '2012-10-17',
                                                   'Statement': statements}))

    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('lambda_function.py',
                    textwrap.dedent(handler_code).strip() + '\n\nlambda_handler = handler\n')
    name = _xname(ctx, 'fn')

    def _attempt():
        try:
            return lam.create_function(
                FunctionName=name,
                Runtime='python3.12',
                Role=role_arn,
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': zip_buf.getvalue()},
                Timeout=30,
                MemorySize=128,
                Environment={'Variables': env},
                Tags=dict(_MANAGED_TAGS),
            )
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'InvalidParameterValueException' or 'cannot be assumed' in str(exc):
                return None
            raise

    # The auto-created log group survives function deletion, so it leaks unless removed here;
    # registered first so it runs after the function is gone and can no longer write to it.
    ctx.on_cleanup(lambda: _swallow(lambda: ctx.client('logs').delete_log_group(
        logGroupName=f'/aws/lambda/{name}')))
    created = _poll_until(
        _attempt, lambda r: r is not None,
        timeout_s=90, interval_s=4.0,
        description=f'CreateFunction {name} to pass the fresh role\'s propagation window',
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get('State') == 'Active',
        timeout_s=120, interval_s=3.0,
        description=f'Lambda {name} to reach State Active',
    )
    return {'name': name, 'arn': created['FunctionArn']}


def _wire_stream_esm(ctx, fn_name: str, source_arn: str, **extra) -> str:
    """A TRIM_HORIZON stream-source ESM. Deliberately does NOT wait for Enabled: the downstream
    effect wait covers activation, which is one wait instead of two serialised ones."""
    lam = ctx.client('lambda')
    params: dict[str, Any] = {
        'FunctionName': fn_name,
        'EventSourceArn': source_arn,
        'Enabled': True,
        'StartingPosition': 'TRIM_HORIZON',
    }
    params.update(extra)
    resp = lam.create_event_source_mapping(**params)
    ctx.on_cleanup(lambda: _swallow(
        lambda: lam.delete_event_source_mapping(UUID=resp['UUID'])))
    return resp['UUID']


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
