"""reserved-concurrency-admission-control-and-metric-agreement-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-concurrency-admission-control-and-metric-agreement-rejected"
GROUP = 'limits'
SERVICES = ['cloudwatch', 'dynamodb', 'lambda']

_RESERVED = 5
_CTL_FANOUT = 20
_REFUSED = 3
_HOLD_S = 3.0
_RENDEZVOUS_S = 30.0
_THROTTLE_MESSAGE = 'Rate Exceeded.'
_THROTTLE_REASON = 'ReservedFunctionConcurrentInvocationLimitExceeded'
# Each invocation registers on a shared counter item and waits until the whole wave has
# registered (bounded), so a wave of N admitted invocations is N in flight at once by
# construction; only then does it hold for _HOLD_S and write its ledger row.
_HANDLER_SRC = """
import os
import time

import boto3

_DDB = boto3.client("dynamodb")


def handler(event, context):
    table = os.environ["LEDGER"]
    key = {"pk": {"S": "RV#" + event["wave"]}}
    _DDB.update_item(TableName=table, Key=key, UpdateExpression="ADD arrived :one",
                     ExpressionAttributeValues={":one": {"N": "1"}})
    deadline = time.time() + event["wait_s"]
    met = False
    while time.time() < deadline:
        item = _DDB.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item", {})
        if int(item.get("arrived", {}).get("N", "0")) >= event["n"]:
            met = True
            break
        time.sleep(0.2)
    t0 = time.time()
    time.sleep(event["hold_s"])
    t1 = time.time()
    _DDB.put_item(TableName=table, Item={
        "pk": {"S": context.aws_request_id},
        "fn": {"S": context.function_name},
        "start": {"N": "%.4f" % t0},
        "end": {"N": "%.4f" % t1},
    })
    return {"rid": context.aws_request_id, "met": met}
"""


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 10 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _zip_bytes(name, src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, src)
    return buf.getvalue()


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
@tags('axis:rejection', 'cap:c3', 'concern:data-plane', 'concern:negative-classes',
      'concern:metrics', 'dp:api', 'plane:data', "timing:real-time")
def run(ctx) -> None:
    """Reserved concurrency 5 admits a 5-way rendezvous wave, reserved 0 refuses every sequential
    invoke with the exact 429 and leaves no ledger row, an unreserved 20-way rendezvous is never
    refused, and Lambda metrics match the client counts exactly.
    """
    # Retries off: botocore would retry a 429 into a success and spoil the client-observed counts.
    lam = ctx.client('lambda', config=Config(retries={'total_max_attempts': 1},
                                             max_pool_connections=_CTL_FANOUT + 10,
                                             read_timeout=120))
    assert lam.meta.config.retries['total_max_attempts'] == 1, (
        f'invoke client resolved retries to {lam.meta.config.retries!r}, expected '
        'total_max_attempts == 1 (no retries at all)'
    )
    iam = ctx.client('iam')
    ddb = ctx.client('dynamodb')
    cw = ctx.client('cloudwatch')
    logs = ctx.client('logs')

    limit = lam.get_account_settings()['AccountLimit']['ConcurrentExecutions']
    assert limit >= _RESERVED + 100 + _CTL_FANOUT, (
        f'this account allows only {limit} concurrent executions; reserving {_RESERVED} keeps '
        f'100 unreserved and the {_CTL_FANOUT}-way control wave needs its own headroom'
    )
    window_lo = (datetime.now(timezone.utc).replace(second=0, microsecond=0)
                 - timedelta(minutes=1))

    ledger = ctx.unique_name('sim2real-behav-ledger-')
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

    role_name = ctx.unique_name('sim2real-behav-lrole-')
    trust = {'Version': '2012-10-17',
             'Statement': [{'Effect': 'Allow',
                            'Principal': {'Service': 'lambda.amazonaws.com'},
                            'Action': 'sts:AssumeRole'}]}
    role_arn = iam.create_role(RoleName=role_name,
                               AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic))
    iam.put_role_policy(RoleName=role_name, PolicyName='ledger-write',
                        PolicyDocument=json.dumps({
                            'Version': '2012-10-17',
                            'Statement': [{'Effect': 'Allow',
                                           'Action': ['dynamodb:PutItem', 'dynamodb:UpdateItem',
                                                      'dynamodb:GetItem'],
                                           'Resource': ledger_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name,
                                                  PolicyName='ledger-write'))

    code = _zip_bytes('lambda_function.py', _HANDLER_SRC)

    def _make_function(label):
        name = ctx.unique_name(f'sim2real-behav-{label}-')
        # IAM role propagation to Lambda exposes no condition to poll, so the bounded retry on the
        # documented InvalidParameterValueException IS the wait -- not a fixed sleep sized to pass.
        deadline = time.time() + 90
        while True:
            try:
                lam.create_function(FunctionName=name, Runtime='python3.12', Role=role_arn,
                                    Handler='lambda_function.handler', Code={'ZipFile': code},
                                    MemorySize=512, Timeout=60,
                                    Environment={'Variables': {'LEDGER': ledger}},
                                    Tags={'sim2real': CHECK})
                break
            except ClientError as exc:
                if (exc.response['Error']['Code'] != 'InvalidParameterValueException'
                        or time.time() >= deadline):
                    raise
                time.sleep(3)
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
        # The log group is created by the SERVICE on first invoke, so it can materialise after the
        # delete above; registered anyway, and tolerant of not existing yet.
        ctx.on_cleanup(lambda: _drop_log_group(logs, f'/aws/lambda/{name}'))
        lam.get_waiter('function_active_v2').wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return name

    fn_reserved = _make_function('fnres')
    fn_control = _make_function('fnctl')
    fn_zero = _make_function('fnzero')

    for fn, want in ((fn_reserved, _RESERVED), (fn_zero, 0)):
        lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=want)
        deadline = time.time() + _budget_s(ctx, 60)
        while True:
            got = lam.get_function_concurrency(
                FunctionName=fn).get('ReservedConcurrentExecutions')
            if got == want:
                break
            assert time.time() < deadline, (
                f'GetFunctionConcurrency for {fn} reported {got!r} rather than {want} within 60s '
                f'of PutFunctionConcurrency'
            )
            time.sleep(2)
    assert lam.get_function_concurrency(
        FunctionName=fn_control).get('ReservedConcurrentExecutions') is None, (
        'the control function reports a reserved concurrency; it must have none, or it is not a '
        'control'
    )

    def _wave(fn, n):
        event = json.dumps({'wave': fn, 'n': n, 'hold_s': _HOLD_S,
                            'wait_s': _RENDEZVOUS_S}).encode()

        def _invoke(_i):
            try:
                resp = lam.invoke(FunctionName=fn, InvocationType='RequestResponse',
                                  Payload=event)
                body = json.loads(resp['Payload'].read())
                return ('ok', body, resp)
            except ClientError as exc:
                return ('err', exc.response, None)
        with ThreadPoolExecutor(max_workers=n) as ex:
            out = list(ex.map(_invoke, range(n)))
        errors = [o[1] for o in out if o[0] == 'err']
        assert errors == [], (
            f'{len(errors)} of {n} invokes of {fn} were refused within its capacity: '
            f'{[(e["Error"]["Code"], e.get("Reason")) for e in errors]!r}'
        )
        bad = [(o[2].get('FunctionError'), o[2]['StatusCode'], o[1]) for o in out
               if o[2].get('FunctionError') or o[2]['StatusCode'] != 200
               or not isinstance(o[1], dict) or o[1].get('met') is not True]
        assert bad == [], (
            f'{len(bad)} of {n} admitted invocations of {fn} failed or never saw all {n} '
            f'registered within {_RENDEZVOUS_S}s (the target must run them concurrently): '
            f'{bad[:3]!r}'
        )
        return [o[1]['rid'] for o in out]

    res_ok = _wave(fn_reserved, _RESERVED)
    ctl_ok = _wave(fn_control, _CTL_FANOUT)

    refusals = []
    for i in range(_REFUSED):
        try:
            resp = lam.invoke(FunctionName=fn_zero, InvocationType='RequestResponse',
                              Payload=json.dumps({'wave': fn_zero, 'n': 1, 'hold_s': 0,
                                                  'wait_s': 1}).encode())
        except ClientError as exc:
            refusals.append(exc.response)
        else:
            raise AssertionError(
                f'invoke {i} of {fn_zero} with ReservedConcurrentExecutions=0 was accepted '
                f'(StatusCode {resp["StatusCode"]!r}); it must be refused'
            )
    for e in refusals:
        assert (e['Error']['Code'], e['Error'].get('Message')) == (
            'TooManyRequestsException', _THROTTLE_MESSAGE), (
            f'reserved-0 refusal carried {e["Error"]!r}, expected TooManyRequestsException '
            f'{_THROTTLE_MESSAGE!r}'
        )
        assert e['ResponseMetadata']['HTTPStatusCode'] == 429, (
            f'reserved-0 refusal carried HTTP {e["ResponseMetadata"]["HTTPStatusCode"]!r}, '
            'expected 429'
        )
        assert e.get('Reason') == _THROTTLE_REASON, (
            f'reserved-0 refusal reported Reason {e.get("Reason")!r}, expected '
            f'{_THROTTLE_REASON!r} -- the account-level ConcurrentInvocationLimitExceeded or an '
            'absent Reason means the modelled limiters are not being discriminated'
        )
        errortype = e['ResponseMetadata']['HTTPHeaders'].get('x-amzn-errortype')
        assert errortype == 'TooManyRequestsException', (
            f'reserved-0 refusal carried x-amzn-errortype {errortype!r}, expected '
            "'TooManyRequestsException'"
        )
    window_hi = (datetime.now(timezone.utc).replace(second=0, microsecond=0)
                 + timedelta(minutes=2))

    # The ledger is the handlers' own testimony: one row per admitted invocation, none for a
    # refused one. Rendezvous counter items are not ledger rows.
    rows = []
    start_key = None
    while True:
        kw = dict(TableName=ledger, ConsistentRead=True)
        if start_key:
            kw['ExclusiveStartKey'] = start_key
        page = ddb.scan(**kw)
        rows.extend(page['Items'])
        start_key = page.get('LastEvaluatedKey')
        if not start_key:
            break
    rows = [r for r in rows if not r['pk']['S'].startswith('RV#')]
    by_fn = {}
    for item in rows:
        by_fn.setdefault(item['fn']['S'], set()).add(item['pk']['S'])
    for fn, admitted in ((fn_reserved, res_ok), (fn_control, ctl_ok)):
        assert by_fn.get(fn, set()) == set(admitted), (
            f'the ledger holds {len(by_fn.get(fn, set()))} rows for {fn} against '
            f'{len(admitted)} admitted invokes; an admitted invocation must not vanish'
        )
    assert fn_zero not in by_fn, (
        f'the ledger holds {len(by_fn[fn_zero])} rows for {fn_zero}, every invoke of which was '
        'refused -- a refused invocation must leave no side effect'
    )
    assert len(rows) == len(res_ok) + len(ctl_ok), (
        f'the ledger holds {len(rows)} rows in total against '
        f'{len(res_ok) + len(ctl_ok)} admitted invocations'
    )

    # Metric AGREEMENT, not presence. Retries are off, so client-observed == server-emitted; the
    # rendezvous held all of the reserved wave in flight at once.
    def _stat(name, fn, stat):
        pts = cw.get_metric_statistics(
            Namespace='AWS/Lambda', MetricName=name,
            Dimensions=[{'Name': 'FunctionName', 'Value': fn}],
            StartTime=window_lo, EndTime=window_hi, Period=60, Statistics=[stat])['Datapoints']
        if not pts:
            return None
        return sum(p[stat] for p in pts) if stat == 'Sum' else max(p[stat] for p in pts)

    want = [
        ('Throttles', fn_zero, 'Sum', float(_REFUSED)),
        ('Invocations', fn_reserved, 'Sum', float(len(res_ok))),
        ('ConcurrentExecutions', fn_reserved, 'Maximum', float(_RESERVED)),
        ('Invocations', fn_control, 'Sum', float(len(ctl_ok))),
    ]
    seen = {}
    deadline = time.time() + _budget_s(ctx, 150)
    while True:
        seen = {(n, f, s): _stat(n, f, s) for n, f, s, _ in want}
        if all(seen[(n, f, s)] == v for n, f, s, v in want):
            break
        if time.time() >= deadline:
            break
        time.sleep(15)
    labels = {fn_reserved: 'reserved', fn_control: 'control', fn_zero: 'reserved-0'}
    for name, fn, stat, expected in want:
        assert seen[(name, fn, stat)] == expected, (
            f'AWS/Lambda {name} {stat} for the {labels[fn]} function is '
            f'{seen[(name, fn, stat)]!r} but the client observed {expected} -- the metric must be '
            f'derived from the same counter that admitted or refused the invokes '
            f'(all metrics: {seen!r})'
        )
    for name, fn in (('Throttles', fn_control), ('Throttles', fn_reserved),
                     ('Invocations', fn_zero)):
        got = _stat(name, fn, 'Sum')
        assert got in (None, 0.0), (
            f'AWS/Lambda {name} Sum for the {labels[fn]} function is {got!r}, expected absent or 0'
        )


def _drop_log_group(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
