"""ddb-stream-esm-partial-batch-response-redelivers-only-the-suffix."""
from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-partial-batch-response-redelivers-only-the-suffix"
GROUP = 'error-propagation'
SERVICES = ['dynamodb', 'lambda']

_MUTATIONS = 5
_FAIL_AT = 2                     # the third mutation is the poison pill
_EFFECT_BUDGET_S = 300


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB Streams ESM with ReportBatchItemFailures redelivers the batch suffix starting at the
    reported record (not just that record, not the whole batch), preserving per-key order, as
    recorded by the handler's audit table."""
    ddb = ctx.client('dynamodb')

    source = _create_table(ctx, 'src', stream=True)
    sink = _create_table(ctx, 'sink')
    ddb.put_item(TableName=sink['name'], Item={'pk': {'S': 'batches'}, 'log': {'L': []}})

    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK_TABLE = os.environ["SINK_TABLE"]
    FAIL_AT = int(os.environ["FAIL_AT"])

    def handler(event, context):
        records = event["Records"]
        versions = [
            int(r["dynamodb"]["NewImage"]["v"]["N"])
            for r in records
            if "NewImage" in r["dynamodb"]
        ]
        ddb.update_item(
            TableName=SINK_TABLE,
            Key={"pk": {"S": "batches"}},
            UpdateExpression="SET #l = list_append(#l, :v)",
            ExpressionAttributeNames={"#l": "log"},
            ExpressionAttributeValues={":v": {"L": [{"S": json.dumps(versions)}]}},
        )
        if FAIL_AT in versions:
            # An atomic counter makes the poison pill fail exactly ONCE, so the retry is
            # guaranteed to succeed and the check terminates instead of looping forever.
            bumped = ddb.update_item(
                TableName=SINK_TABLE,
                Key={"pk": {"S": "failures"}},
                UpdateExpression="SET n = if_not_exists(n, :z) + :o",
                ExpressionAttributeValues={":z": {"N": "0"}, ":o": {"N": "1"}},
                ReturnValues="UPDATED_NEW",
            )
            if int(bumped["Attributes"]["n"]["N"]) == 1:
                idx = versions.index(FAIL_AT)
                return {"batchItemFailures": [
                    {"itemIdentifier": records[idx]["dynamodb"]["SequenceNumber"]}
                ]}
        return {"batchItemFailures": []}
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {'Action': ['dynamodb:GetRecords', 'dynamodb:GetShardIterator',
                        'dynamodb:DescribeStream', 'dynamodb:ListStreams'],
             'Resource': f'{source["arn"]}/stream/*'},
            {'Action': ['dynamodb:UpdateItem'], 'Resource': sink['arn']},
        ],
        env={'SINK_TABLE': sink['name'], 'FAIL_AT': str(_FAIL_AT)},
    )

    # The mutations are committed BEFORE the ESM exists, so one TRIM_HORIZON wait downstream covers
    # both ESM activation and delivery instead of two serialised waits.
    key = {'pk': {'S': 'ordered-item'}}
    ddb.put_item(TableName=source['name'], Item={**key, 'v': {'N': '0'}})
    for version in range(1, _MUTATIONS):
        ddb.update_item(
            TableName=source['name'], Key=key,
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={':v': {'N': str(version)}},
        )

    _wire_stream_esm(
        ctx, fn['name'], source['stream_arn'],
        BatchSize=10,
        MaximumBatchingWindowInSeconds=0,
        FunctionResponseTypes=['ReportBatchItemFailures'],
        MaximumRetryAttempts=3,
    )

    def _batches():
        item = ddb.get_item(TableName=sink['name'],
                            Key={'pk': {'S': 'batches'}}).get('Item')
        return [json.loads(entry['S']) for entry in item['log']['L']] if item else []

    def _saw_retry(batches):
        for i, batch in enumerate(batches):
            if _FAIL_AT in batch and i + 1 < len(batches):
                return True
        return False

    batches = _poll_until(
        _batches, _saw_retry,
        timeout_s=_EFFECT_BUDGET_S, interval_s=5.0,
        description=(
            f'a redelivery AFTER the batch containing the reported failure (mutation {_FAIL_AT}); '
            f'without one there is no suffix to inspect and the ESM never honoured the '
            f'batchItemFailures response'
        ),
    )

    fail_index = next(i for i, b in enumerate(batches) if _FAIL_AT in b)
    failed_batch = batches[fail_index]
    position = failed_batch.index(_FAIL_AT)
    expected_retry = failed_batch[position:]
    retry_batch = batches[fail_index + 1]

    assert retry_batch == expected_retry, (
        f'ReportBatchItemFailures on a DynamoDB Streams source must redeliver the SUFFIX starting at '
        f'the reported record. failed batch {failed_batch!r}; reported mutation {_FAIL_AT!r} at index '
        f'{position!r}; expected retry {expected_retry!r}; actual retry {retry_batch!r}; all batches '
        f'{batches!r}'
    )
    already_checkpointed = ({v for b in batches[:fail_index] for v in b}
                            | set(failed_batch[:position]))
    redelivered_later = {v for b in batches[fail_index + 1:] for v in b}
    assert not (already_checkpointed & redelivered_later), (
        f'records checkpointed before the reported failure must never be redelivered: '
        f'{sorted(already_checkpointed & redelivered_later)!r} came back. That is whole-batch retry, '
        f'not ReportBatchItemFailures, and it double-applies changes to one item. batches={batches!r}'
    )
    assert len(expected_retry) > 1, (
        f'the reported record was the last of its batch, so this run cannot distinguish suffix '
        f'redelivery from single-record redelivery: failed batch {failed_batch!r}. The mutations were '
        f'committed before the ESM existed precisely so they would batch together; batches='
        f'{batches!r}'
    )
    assert {v for b in batches for v in b} == set(range(_MUTATIONS)), (
        f'the pipeline must still drain: every one of the {_MUTATIONS!r} mutations must reach the '
        f'consumer at least once, got {sorted({v for b in batches for v in b})!r} across '
        f'{batches!r}'
    )
    # Order within one item's records is DynamoDB's guarantee, so every batch the consumer saw must
    # be ascending in version.
    for i, batch in enumerate(batches):
        assert batch == sorted(batch), (
            f'DynamoDB Streams delivers one item\'s records in modification order, so batch {i!r} '
            f'must be ascending in version, got {batch!r}; all batches {batches!r}'
        )
    failures = ddb.get_item(TableName=sink['name'], Key={'pk': {'S': 'failures'}},
                            ConsistentRead=True).get('Item')
    assert failures is not None and int(failures['n']['N']) >= 1, (
        f'the handler must have reached its failure branch at least once, or the redelivery above '
        f'was not caused by a reported batch item failure; the counter reads {failures!r}'
    )


# ===== helpers =====
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
    """Teardown-only: a cleanup step that has already been done must not mask the real verdict."""
    try:
        fn()
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(f'teardown step failed: {exc}') from exc


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
    """A Lambda plus an execution role scoped to `permissions`; logs are always allowed.

    The role-propagation window is absorbed by a bounded create_function retry rather than by a
    sleep, so nothing here forks on the transport.
    """
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
            if code in ('InvalidParameterValueException',) or 'cannot be assumed' in str(exc):
                return None
            raise

    created = _poll_until(
        _attempt, lambda r: r is not None,
        timeout_s=90, interval_s=4.0,
        description=f'CreateFunction {name} to pass the fresh role\'s propagation window',
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    # The auto-created log group survives function deletion, so it leaks unless removed here.
    ctx.on_cleanup(lambda: _swallow(lambda: ctx.client('logs').delete_log_group(
        logGroupName=f'/aws/lambda/{name}')))
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
