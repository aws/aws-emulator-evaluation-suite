"""ddb-stream-esm-bisect-on-function-error-isolates-the-poison-record."""
from __future__ import annotations

import json
import math
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-esm-bisect-on-function-error-isolates-the-poison-record"
GROUP = 'error-propagation'
SERVICES = ['dynamodb', 'lambda']

_MUTATIONS = 8
_POISON = 3                      # strictly inside the batch, so a split can exclude it
_RETRY_ATTEMPTS = 2
_EFFECT_BUDGET_S = 420


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """With BisectBatchOnFunctionError=True, a DynamoDB-stream ESM whose handler raises re-delivers
    the batch as strictly smaller batches so the poison-free half completes, while an otherwise
    identical ESM with the flag off re-delivers the identical whole batch and never a subset."""
    ddb = ctx.client('dynamodb')

    sink = _create_table(ctx, 'audit')
    ddb.put_item(TableName=sink['name'], Item={'pk': {'S': 'log'}, 'entries': {'L': []}})
    subject = _create_table(ctx, 'src-bisect', stream=True)
    control = _create_table(ctx, 'src-whole', stream=True)

    code = """
    import json, os
    import boto3
    ddb = boto3.client("dynamodb")
    SINK_TABLE = os.environ["SINK_TABLE"]
    POISON = int(os.environ["POISON"])

    def handler(event, context):
        records = event["Records"]
        # arn:aws:dynamodb:<region>:<acct>:table/<name>/stream/<label>
        source = records[0]["eventSourceARN"].split(":table/")[1].split("/stream/")[0]
        versions = [
            int(r["dynamodb"]["NewImage"]["v"]["N"])
            for r in records
            if "NewImage" in r["dynamodb"]
        ]
        poisoned = POISON in versions
        entry = {"src": source, "b": versions, "ok": 0 if poisoned else 1}
        ddb.update_item(
            TableName=SINK_TABLE,
            Key={"pk": {"S": "log"}},
            UpdateExpression="SET #e = list_append(#e, :v)",
            ExpressionAttributeNames={"#e": "entries"},
            ExpressionAttributeValues={":v": {"L": [{"S": json.dumps(entry)}]}},
        )
        if poisoned:
            raise RuntimeError(f"poison record {POISON} in batch {versions}")
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
        env={'SINK_TABLE': sink['name'], 'POISON': str(_POISON)},
    )

    # Both sources are mutated identically and BEFORE either ESM exists, so one TRIM_HORIZON wait
    # covers activation and delivery for both and no propagation delta exists between the twins.
    key = {'pk': {'S': 'ordered-item'}}
    for table in (subject['name'], control['name']):
        ddb.put_item(TableName=table, Item={**key, 'v': {'N': '0'}})
        for version in range(1, _MUTATIONS):
            ddb.update_item(
                TableName=table, Key=key,
                UpdateExpression='SET v = :v',
                ExpressionAttributeValues={':v': {'N': str(version)}},
            )

    _wire_stream_esm(ctx, fn['name'], subject['stream_arn'],
                     BatchSize=_MUTATIONS + 2,
                     MaximumBatchingWindowInSeconds=0,
                     MaximumRetryAttempts=_RETRY_ATTEMPTS,
                     BisectBatchOnFunctionError=True)
    _wire_stream_esm(ctx, fn['name'], control['stream_arn'],
                     BatchSize=_MUTATIONS + 2,
                     MaximumBatchingWindowInSeconds=0,
                     MaximumRetryAttempts=_RETRY_ATTEMPTS,
                     BisectBatchOnFunctionError=False)

    def _entries():
        item = ddb.get_item(TableName=sink['name'], Key={'pk': {'S': 'log'}},
                            ConsistentRead=True).get('Item')
        return [json.loads(e['S']) for e in item['entries']['L']] if item else []

    def _for(entries, table_name):
        return [e for e in entries if e['src'] == table_name]

    def _both_legs_settled(entries):
        subj = _for(entries, subject['name'])
        ctrl = _for(entries, control['name'])
        if not subj or not ctrl:
            return False
        subject_split = any(e['ok'] == 1 and len(e['b']) < len(subj[0]['b'])
                            for e in subj[1:])
        control_poisoned = [tuple(e['b']) for e in ctrl if e['ok'] == 0]
        control_retried = (len(control_poisoned) >= 2
                           and control_poisoned[0] in control_poisoned[1:])
        return subject_split and control_retried

    entries = _poll_until(
        _entries, _both_legs_settled,
        timeout_s=_EFFECT_BUDGET_S, interval_s=5.0,
        description=(
            'the bisecting ESM to deliver a poison-free SUBSET of its first batch that completes, and '
            'the non-bisecting ESM to re-deliver its poison-bearing batch UNCHANGED -- neither leg is '
            'evidence without the other'
        ),
    )

    subj = _for(entries, subject['name'])
    ctrl = _for(entries, control['name'])
    assert subj and ctrl, (
        f'both ESMs must have delivered something: subject saw {len(subj)!r} batches, control saw '
        f'{len(ctrl)!r}; entries={entries!r}'
    )

    # --- the run must be able to discriminate at all ---
    first = subj[0]['b']
    assert len(first) >= 4 and _POISON in first[1:-1], (
        f'this run cannot distinguish bisection from whole-batch retry: the subject\'s first batch was '
        f'{first!r} and the poison record {_POISON!r} must sit strictly inside a batch of at least 4 '
        f'so that a half exists which excludes it. The mutations were committed before the ESM existed '
        f'precisely so they would batch together. entries={entries!r}'
    )
    assert subj[0]['ok'] == 0, (
        f'the subject\'s first batch contains the poison record {_POISON!r} and so must have failed, '
        f'got ok={subj[0]["ok"]!r} for {first!r}'
    )

    # --- SUBJECT: the failing batch was split, and the poison-free half went through ---
    clean_halves = [e['b'] for e in subj[1:]
                    if e['ok'] == 1 and set(e['b']) < set(first)]
    assert clean_halves, (
        f'BisectBatchOnFunctionError=True must split the failed batch so that the part without the '
        f'poison record is processed: no batch after the first was a proper subset of {first!r} that '
        f'completed. The subject saw {[(e["b"], e["ok"]) for e in subj]!r}, which is whole-batch '
        f'retry -- one bad record stalls every good record behind it'
    )
    assert _POISON not in clean_halves[0], (
        f'the successfully processed half must not contain the poison record {_POISON!r}: '
        f'{clean_halves[0]!r}'
    )
    poisoned_subsets = [e['b'] for e in subj[1:]
                        if e['ok'] == 0 and set(e['b']) < set(first)]
    assert poisoned_subsets, (
        f'the poison-bearing side must be split too, not merely the good side: no failing batch after '
        f'the first was a proper subset of {first!r}. Subject saw '
        f'{[(e["b"], e["ok"]) for e in subj]!r}'
    )
    half = math.ceil(len(first) / 2)
    smallest_poisoned = min(len(b) for b in poisoned_subsets)
    assert smallest_poisoned <= half, (
        f'"split the batch in two" means the retried halves are at most ceil({len(first)!r}/2) = '
        f'{half!r} records; the smallest poison-bearing retry was {smallest_poisoned!r} records. '
        f'Subject saw {[(e["b"], e["ok"]) for e in subj]!r}'
    )
    # Bisection must not invent or lose records: everything it ever delivered came from the first
    # batch, and the poison-free half plus the poison-bearing half cover it.
    delivered = {v for e in subj for v in e['b']}
    assert delivered == set(first), (
        f'bisection must only ever re-deliver records from the batch that failed: the subject saw '
        f'{sorted(delivered)!r}, its first batch was {sorted(first)!r}'
    )

    # --- CONTROL: same wiring, flag off, so a retry is the IDENTICAL batch ---
    control_first = ctrl[0]['b']
    control_poisoned = [e['b'] for e in ctrl if e['ok'] == 0]
    assert len(control_poisoned) >= 2, (
        f'the control ESM must have retried its failing batch at least once, or its "no split" claim '
        f'is vacuous: it saw {[(e["b"], e["ok"]) for e in ctrl]!r}'
    )
    assert control_poisoned[1] == control_poisoned[0], (
        f'with BisectBatchOnFunctionError=False a retry must re-deliver the IDENTICAL batch: first '
        f'failure {control_poisoned[0]!r}, retry {control_poisoned[1]!r}'
    )
    split_on_control = [b for b in control_poisoned[1:] if set(b) < set(control_poisoned[0])]
    assert not split_on_control, (
        f'BisectBatchOnFunctionError=False must never split: the control re-delivered '
        f'{split_on_control!r}, a proper subset of its failing batch {control_poisoned[0]!r}. An '
        f'implementation that bisects unconditionally changes batch sizes for every customer who did '
        f'not ask for it'
    )
    assert set(control_first) == set(subj[0]['b']), (
        f'the twins must have been handed the same work for the comparison to mean anything: control '
        f'first batch {sorted(control_first)!r} vs subject first batch {sorted(first)!r}'
    )

    # --- and the source data itself is intact in both tables (at the producer's store) ---
    for table in (subject['name'], control['name']):
        stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
        assert stored == {**key, 'v': {'N': str(_MUTATIONS - 1)}}, (
            f'a failing consumer must not affect the source table {table!r}; GetItem returned '
            f'{stored!r}, expected v={_MUTATIONS - 1!r}'
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
    """Teardown-only: a cleanup step already done must not mask the real verdict."""
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
            if code == 'InvalidParameterValueException' or 'cannot be assumed' in str(exc):
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
