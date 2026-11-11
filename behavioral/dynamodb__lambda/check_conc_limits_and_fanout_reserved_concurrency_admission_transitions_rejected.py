"""conc-limits-and-fanout-reserved-concurrency-admission-transitions-rejected."""
from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-limits-and-fanout-reserved-concurrency-admission-transitions-rejected"
GROUP = 'concurrency_rejected'
SERVICES = ['dynamodb', 'lambda']

_WAVE = 8          # simultaneous synchronous invokes per wave
_HOLD_S = 5        # each admitted execution holds its slot this long
_RAISED = 3        # the reservation the second phase raises to
_REFUSAL = 'TooManyRequestsException'

_HANDLER_SRC = '''
import os
import time
import uuid

import boto3

_DDB = boto3.client("dynamodb")
_ENV = uuid.uuid4().hex


def handler(event, context):
    time.sleep(float(event.get("hold", 0)))
    _DDB.put_item(TableName=os.environ["LEDGER"], Item={
        "pk": {"S": "%s#%s" % (event["wave"], event["idx"])},
        "env": {"S": _ENV},
    })
    return {"env": _ENV, "idx": event["idx"]}
'''


def _zip_bytes(name, src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, src)
    return buf.getvalue()


def _reap_log_group(logs, group):
    """delete_function does not remove /aws/lambda/<fn>, and a buffered flush can recreate the
    group after a delete -- so delete, watch for reappearance, and repeat a bounded number of
    rounds. Never raises; a group that will not stay deleted is reported as a leak."""
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ResourceNotFoundException':
                raise RuntimeError(f'could not delete {group}: {exc}') from exc
        deadline = time.time() + 8
        back = False
        while time.time() < deadline:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get('logGroups', [])
            if any(g['logGroupName'] == group for g in found):
                back = True
                break
            time.sleep(2)
        if not back:
            return
    raise RuntimeError(f'log group {group} kept reappearing after delete')


def _scan_all(ddb, table):
    rows, start = [], None
    while True:
        kw = {'TableName': table, 'ConsistentRead': True}
        if start:
            kw['ExclusiveStartKey'] = start
        page = ddb.scan(**kw)
        rows.extend(page['Items'])
        start = page.get('LastEvaluatedKey')
        if not start:
            return rows


@tags('axis:rejection', 'cap:c3', 'concern:data-plane', 'concern:negative-classes',
      'dp:api', 'plane:data')
def run(ctx) -> None:
    """An 8-way simultaneous wave admits exactly 1, 3, 0, then 8 invokes as reserved concurrency
    moves 1 -> 3 -> 0 -> unreserved; refusals are TooManyRequestsException and leave no ledger row,
    so a refusal is a real refusal, not a mislabelled execution.
    """
    lam_ctl = ctx.client('lambda')
    # Retries OFF: botocore's default retry would turn a 429 into a later success and destroy
    # the exact admitted/refused split this check counts.
    lam = ctx.client('lambda', config=Config(retries={'total_max_attempts': 1},
                                             max_pool_connections=_WAVE + 4,
                                             read_timeout=120))
    assert lam.meta.config.retries['total_max_attempts'] == 1, (
        f'invoke client resolved retries to {lam.meta.config.retries!r}; expected no retries'
    )
    iam = ctx.client('iam')
    ddb = ctx.client('dynamodb')
    logs = ctx.client('logs')

    settings = lam_ctl.get_account_settings()['AccountLimit']
    # A reservation must leave 100 unreserved; the account limit is read, never assumed.
    assert settings['UnreservedConcurrentExecutions'] >= 100 + _RAISED + _WAVE, (
        f'account reports UnreservedConcurrentExecutions={settings["UnreservedConcurrentExecutions"]!r};'
        f' this check needs at least {100 + _RAISED + _WAVE} to reserve {_RAISED} and run an '
        f'unreserved {_WAVE}-way control wave'
    )

    ledger = ctx.unique_name('sim2real-conc-ledger-')
    ddb.create_table(
        TableName=ledger,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=ledger))
    ddb.get_waiter('table_exists').wait(TableName=ledger, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ledger_arn = ddb.describe_table(TableName=ledger)['Table']['TableArn']

    role_name = ctx.unique_name('sim2real-conc-role-')
    trust = {'Version': '2012-10-17',
             'Statement': [{'Effect': 'Allow',
                            'Principal': {'Service': 'lambda.amazonaws.com'},
                            'Action': 'sts:AssumeRole'}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Description='sim2real ' + CHECK,
                               Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic))
    iam.put_role_policy(RoleName=role_name, PolicyName='ledger-write', PolicyDocument=json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Action': 'dynamodb:PutItem', 'Resource': ledger_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName='ledger-write'))

    fn = ctx.unique_name('sim2real-conc-fn-')
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f'/aws/lambda/{fn}'))
    # IAM propagation exposes no pollable condition; the bounded retry on the documented
    # "role cannot be assumed" InvalidParameterValueException is the wait.
    deadline = time.time() + 90
    while True:
        try:
            lam_ctl.create_function(
                FunctionName=fn, Runtime='python3.12', Role=role_arn,
                Handler='lambda_function.handler',
                Code={'ZipFile': _zip_bytes('lambda_function.py', _HANDLER_SRC)},
                MemorySize=256, Timeout=60,
                Environment={'Variables': {'LEDGER': ledger}}, Tags={'sim2real': CHECK})
            break
        except ClientError as exc:
            if (exc.response['Error']['Code'] != 'InvalidParameterValueException'
                    or time.time() >= deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam_ctl.delete_function(FunctionName=fn))
    lam_ctl.get_waiter('function_active_v2').wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    wave_no = [0]

    def _wave(hold=_HOLD_S):
        wave_no[0] += 1
        wid = f'w{wave_no[0]}'

        def _one(idx):
            try:
                resp = lam.invoke(FunctionName=fn, InvocationType='RequestResponse',
                                  Payload=json.dumps({'wave': wid, 'idx': idx,
                                                      'hold': hold}).encode())
                body = json.loads(resp['Payload'].read())
                return idx, ('ok', resp.get('FunctionError'), body)
            except ClientError as exc:
                return idx, ('refused', exc.response['Error'].get('Code'),
                             exc.response.get('Reason'), exc.response['Error'].get('Message'))
        with ThreadPoolExecutor(max_workers=_WAVE) as pool:
            out = dict(pool.map(_one, range(_WAVE)))
        ok = {i for i, o in out.items() if o[0] == 'ok'}
        refused = {i: (o[1], o[2]) for i, o in out.items() if o[0] == 'refused'}
        refused_messages = {i: o[3] for i, o in out.items() if o[0] == 'refused'}
        errs = {i: o for i, o in out.items() if o[0] == 'ok' and o[1]}
        assert not errs, f'wave {wid}: admitted invokes raised a FunctionError: {errs!r}'
        return wid, ok, refused, refused_messages, out

    def _ledger_idx(wid):
        return {int(r['pk']['S'].split('#', 1)[1]) for r in _scan_all(ddb, ledger)
                if r['pk']['S'].split('#', 1)[0] == wid}

    # Positive control and warm-up, before any reservation: one invoke runs and writes its row.
    # Bounded retry on FunctionError only -- the inline ledger policy may still be propagating.
    deadline = time.time() + 90
    while True:
        wave_no[0] += 1
        wid = f'w{wave_no[0]}'
        resp = lam_ctl.invoke(FunctionName=fn, Payload=json.dumps(
            {'wave': wid, 'idx': 0, 'hold': 0}).encode())
        resp['Payload'].read()
        if not resp.get('FunctionError'):
            break
        assert time.time() < deadline, (
            f'the unreserved warm-up invoke kept failing with FunctionError '
            f'{resp.get("FunctionError")!r} for 90s -- the handler cannot write its ledger row'
        )
        time.sleep(5)
    assert _ledger_idx(wid) == {0}, (
        f'the warm-up invoke returned 200 but its ledger row is {_ledger_idx(wid)!r}, not {{0}}'
    )

    def _set_reserved(n):
        lam_ctl.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=n)
        got = lam_ctl.get_function_concurrency(FunctionName=fn).get('ReservedConcurrentExecutions')
        assert got == n, f'GetFunctionConcurrency reported {got!r} after setting {n}'

    def _until(pred, what):
        # Enforcement propagates asynchronously after the API confirms the setting, and its only
        # observable IS admission -- so the wait is a bounded series of real waves.
        deadline = time.time() + 120
        last = None
        while True:
            last = _wave()
            if pred(last):
                return
            assert time.time() < deadline, (
                f'{what} never took effect on the invoke path within 120s; last wave admitted '
                f'{sorted(last[1])!r} and refused {sorted(last[2])!r}'
            )
            time.sleep(3)

    def _assert_measured(label, want_ok):
        wid, ok, refused, refused_messages, out = _wave()
        assert len(ok) == want_ok, (
            f'{label}: {len(ok)} of {_WAVE} simultaneous invokes were admitted '
            f'({sorted(ok)!r}), expected exactly {want_ok}; outcomes {out!r}'
        )
        codes = {c for c, _ in refused.values()}
        assert len(refused) == _WAVE - want_ok, (
            f'{label}: {len(refused)} refused, expected {_WAVE - want_ok}'
        )
        if refused:
            assert codes == {_REFUSAL}, (
                f'{label}: refusals carried {sorted(map(repr, codes))}, expected exactly '
                f'{{{_REFUSAL!r}}}'
            )
            assert set(refused_messages.values()) == {'Rate Exceeded.'}, (
                f'{label}: refusal messages {sorted(map(repr, set(refused_messages.values())))}, '
                f"expected exactly {{'Rate Exceeded.'}}"
            )
        # Effect-absent: the ledger holds rows for exactly the admitted indices of THIS wave.
        rows = _ledger_idx(wid)
        assert rows == ok, (
            f'{label}: ledger rows for wave {wid} are {sorted(rows)!r} but the admitted set was '
            f'{sorted(ok)!r} -- a refused invocation must leave no side effect and an admitted '
            f'one must not vanish'
        )
        return ok, refused, out

    # Phase 1: reserved = 1 -> exactly one admitted, seven refused, seven absent rows.
    _set_reserved(1)
    _until(lambda w: len(w[2]) > 0, 'ReservedConcurrentExecutions=1')
    ok1, refused1, _ = _assert_measured('reserved=1', 1)
    reasons1 = {r for _, r in refused1.values()}
    assert reasons1 == {'ReservedFunctionConcurrentInvocationLimitExceeded'}, (
        f'reserved=1 refusals reported Reason {sorted(map(repr, reasons1))}, expected the '
        f'reserved-function limiter specifically'
    )

    # Phase 2: raise to 3 -> the gate widens to exactly three.
    _set_reserved(_RAISED)
    _until(lambda w: len(w[1]) > 1, f'raising ReservedConcurrentExecutions to {_RAISED}')
    ok2, _, out2 = _assert_measured(f'reserved={_RAISED}', _RAISED)
    warm_envs = {out2[i][2]['env'] for i in ok2}
    assert len(warm_envs) == _RAISED, (
        f'{_RAISED} admitted executions overlapped for {_HOLD_S}s but ran in '
        f'{len(warm_envs)} distinct environments {sorted(warm_envs)!r}; concurrent executions '
        f'cannot share one'
    )

    # Phase 3: reserved = 0 -> everything refused, including the path warm environments serve.
    _set_reserved(0)
    _until(lambda w: len(w[1]) == 0, 'ReservedConcurrentExecutions=0')
    _assert_measured('reserved=0 (warm environments existed)', 0)

    # Phase 4: remove the reservation -> the whole wave is admitted again.
    lam_ctl.delete_function_concurrency(FunctionName=fn)
    assert lam_ctl.get_function_concurrency(FunctionName=fn).get(
        'ReservedConcurrentExecutions') is None, 'DeleteFunctionConcurrency left a reservation'
    _until(lambda w: len(w[1]) == _WAVE, 'removing the reservation')
    _assert_measured('unreserved', _WAVE)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
