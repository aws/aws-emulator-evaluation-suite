"""conc-limits-and-fanout-sqs-esm-partial-batch-redelivers-exactly-reported-items."""
from __future__ import annotations

import io
import json
import sys
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-limits-and-fanout-sqs-esm-partial-batch-redelivers-exactly-reported-items"
GROUP = 'event_source_mapping'
SERVICES = ['dynamodb', 'lambda', 'sqs']

_MODE = 'partial'
_N = 10
_TARGETS = (3, 7)       # the items the handler reports as failed, on their FIRST delivery only
_SENTINEL = 99
_VT = 8                 # queue VisibilityTimeout; must be >= the function Timeout
_FN_TIMEOUT = 6

_HANDLER_SRC = '''
import json
import os

import boto3

_DDB = boto3.client("dynamodb")
_T = os.environ["TALLY"]
_MODE = os.environ["MODE"]
_TARGETS = {int(x) for x in os.environ["TARGETS"].split(",")}


def handler(event, context):
    recs = event["Records"]
    counts, ids = {}, {}
    for r in recs:
        idx = int(json.loads(r["body"])["idx"])
        ids[idx] = r["messageId"]
        resp = _DDB.update_item(
            TableName=_T, Key={"pk": {"S": "m#%d" % idx}},
            UpdateExpression="ADD deliveries :one",
            ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW")
        counts[idx] = int(resp["Attributes"]["deliveries"]["N"])
    hit = sorted(i for i in counts if i in _TARGETS and counts[i] == 1)
    _DDB.put_item(TableName=_T, Item={
        "pk": {"S": "inv#" + context.aws_request_id},
        "idxs": {"S": json.dumps(sorted(counts))},
        "hit": {"S": json.dumps(hit)},
    })
    if _MODE == "partial":
        return {"batchItemFailures": [{"itemIdentifier": ids[i]} for i in hit]}
    if hit and _MODE == "throw":
        raise RuntimeError("sim2real deliberate whole-batch failure")
    if hit and _MODE == "invalid":
        return {"batchItemFailures": [{"itemIdentifier": "sim2real-not-a-message-id"}]}
    return {"batchItemFailures": []}
'''


def _zip_bytes(name, src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, src)
    return buf.getvalue()


def _reap_log_group(logs, group):
    """delete_function leaves /aws/lambda/<fn>, and a late flush can recreate it: delete, watch
    for reappearance, repeat a bounded number of rounds. Never raises."""
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


def _delete_esm(lam, uuid):
    try:
        lam.delete_event_source_mapping(UUID=uuid)
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        return
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            lam.get_event_source_mapping(UUID=uuid)
        except ClientError as exc:
            if exc.response['Error']['Code'] == 'ResourceNotFoundException':
                return
            raise
        time.sleep(3)
    raise RuntimeError(f'event source mapping {uuid} still present 90s after delete')


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


def _tallies(ddb, table):
    tally, invocations = {}, []
    for r in _scan_all(ddb, table):
        pk = r['pk']['S']
        if pk.startswith('m#'):
            tally[int(pk[2:])] = int(r['deliveries']['N'])
        elif pk.startswith('inv#'):
            invocations.append((json.loads(r['idxs']['S']), json.loads(r['hit']['S'])))
    return tally, invocations


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_esm_state(ctx, lam, uuid, want, budget_s=180):
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.time() + budget_s
    last = None
    while time.time() < deadline:
        last = lam.get_event_source_mapping(UUID=uuid)
        if last['State'] == want:
            return last
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f'event source mapping {uuid} reaching {want!r}: the run budget ended first; not graded')
    raise AssertionError(f'event source mapping {uuid} never reached {want!r} in {budget_s:.0f}s; '
                         f'last State={last and last.get("State")!r} '
                         f'StateTransitionReason={last and last.get("StateTransitionReason")!r}')


def _build(ctx, mode, targets):
    """Queue + tally table + role + function + DISABLED mapping, every teardown registered at
    creation. Returns the handles the scenario needs."""
    sqs = ctx.client('sqs')
    ddb = ctx.client('dynamodb')
    iam = ctx.client('iam')
    lam = ctx.client('lambda')
    logs = ctx.client('logs')

    qname = ctx.unique_name('sim2real-conc-esm-')[:70] + '.fifo'
    url = sqs.create_queue(QueueName=qname, Attributes={
        'FifoQueue': 'true', 'VisibilityTimeout': str(_VT)}, tags={'sim2real': CHECK})['QueueUrl']
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    qarn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']

    table = ctx.unique_name('sim2real-conc-tally-')
    ddb.create_table(TableName=table,
                     KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    tarn = ddb.describe_table(TableName=table)['Table']['TableArn']

    role = ctx.unique_name('sim2real-conc-esmrole-')
    trust = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
        'Action': 'sts:AssumeRole'}]}
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust),
                               Description='sim2real ' + CHECK,
                               Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    basic = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
    iam.attach_role_policy(RoleName=role, PolicyArn=basic)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role, PolicyArn=basic))
    iam.put_role_policy(RoleName=role, PolicyName='esm', PolicyDocument=json.dumps({
        'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Resource': qarn,
             'Action': ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes',
                        'sqs:ChangeMessageVisibility']},
            {'Effect': 'Allow', 'Resource': tarn,
             'Action': ['dynamodb:UpdateItem', 'dynamodb:PutItem']}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName='esm'))

    fn = ctx.unique_name('sim2real-conc-esmfn-')
    ctx.on_cleanup(lambda: _reap_log_group(logs, f'/aws/lambda/{fn}'))
    # IAM propagation has no pollable condition: the bounded retry on the documented
    # "role cannot be assumed" InvalidParameterValueException is the wait.
    deadline = time.time() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime='python3.12', Role=role_arn,
                Handler='lambda_function.handler',
                Code={'ZipFile': _zip_bytes('lambda_function.py', _HANDLER_SRC)},
                MemorySize=256, Timeout=_FN_TIMEOUT,
                Environment={'Variables': {'TALLY': table, 'MODE': mode,
                                           'TARGETS': ','.join(map(str, targets))}},
                Tags={'sim2real': CHECK})
            break
        except ClientError as exc:
            if (exc.response['Error']['Code'] != 'InvalidParameterValueException'
                    or time.time() >= deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter('function_active_v2').wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    deadline = time.time() + 90
    while True:
        try:
            uuid = lam.create_event_source_mapping(
                EventSourceArn=qarn, FunctionName=fn, BatchSize=10, Enabled=False,
                FunctionResponseTypes=['ReportBatchItemFailures'])['UUID']
            break
        except ClientError as exc:
            # The mapping validates the role's SQS permissions, which may still be propagating.
            if (exc.response['Error']['Code'] != 'InvalidParameterValueException'
                    or time.time() >= deadline):
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_esm(lam, uuid))
    _wait_esm_state(ctx, lam, uuid, 'Disabled')
    return sqs, ddb, lam, url, table, uuid


def _send(sqs, url, idxs):
    entries = [{'Id': f'e{i}', 'MessageBody': json.dumps({'idx': i}),
                'MessageGroupId': f'g{i}', 'MessageDeduplicationId': f'd{i}'} for i in idxs]
    for k in range(0, len(entries), 10):
        resp = sqs.send_message_batch(QueueUrl=url, Entries=entries[k:k + 10])
        assert not resp.get('Failed'), f'send_message_batch failures: {resp["Failed"]!r}'


def _poll_tally(ctx, ddb, table, pred, what, budget_s=150):
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.time() + budget_s
    tally, inv = {}, []
    while time.time() < deadline:
        tally, inv = _tallies(ddb, table)
        if pred(tally, inv):
            return tally, inv
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f'{what}: the run budget ended first; not graded')
    raise AssertionError(f'{what} within {budget_s:.0f}s; tally={tally!r} invocations={inv!r}')


def _drained(ctx, sqs, url, budget_s=90):
    """Barrier: the queue reports nothing visible, in flight or delayed on several consecutive
    reads (the counters are approximate, so one zero is not enough)."""
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.time() + budget_s
    zeros = 0
    attrs = {}
    while time.time() < deadline:
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[
            'ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible',
            'ApproximateNumberOfMessagesDelayed'])['Attributes']
        zeros = zeros + 1 if all(v == '0' for v in attrs.values()) else 0
        if zeros >= 3:
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError('queue draining to empty: the run budget ended first; not graded')
    raise AssertionError(f'queue never drained to empty within {budget_s:.0f}s: {attrs!r}')


@tags("cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """An SQS event-source mapping with ReportBatchItemFailures redelivers exactly the reported
    items: items 3 and 7 are delivered exactly twice and the other eight exactly once.
    """
    # FIFO with one MessageGroupId per message: FIFO's no-duplicate guarantee makes an exact tally
    # assertable, and one group per message keeps in-group blocking away from the failures.
    sqs, ddb, lam, url, table, uuid = _build(ctx, _MODE, _TARGETS)
    _send(sqs, url, range(_N))
    lam.update_event_source_mapping(UUID=uuid, Enabled=True)
    _wait_esm_state(ctx, lam, uuid, 'Enabled')

    # Positive control first: all ten are delivered at least once, and the targets were reported.
    _poll_tally(ctx, ddb, table, lambda t, inv: set(t) >= set(range(_N)),
                'not every message was delivered even once')
    # The reported pair comes back once its visibility timeout lapses.
    _poll_tally(ctx, ddb, table, lambda t, inv: all(t.get(i) == 2 for i in _TARGETS),
                f'items {_TARGETS} were not redelivered after being reported as failed')

    # Barrier, then the exact tally. The other eight shared the failed pair's visibility window, so
    # any redelivery of theirs would already have come with it.
    _send(sqs, url, [_SENTINEL])
    _poll_tally(ctx, ddb, table, lambda t, inv: t.get(_SENTINEL) == 1,
                'the sentinel sent after the redelivery was never processed')
    _drained(ctx, sqs, url)
    tally, invocations = _tallies(ddb, table)

    reported = sorted(i for _, hit in invocations for i in hit)
    assert reported == sorted(_TARGETS), (
        f'the handler reported {reported!r} as failed across {len(invocations)} invocations; the '
        f'scenario requires exactly {sorted(_TARGETS)!r}, each once'
    )
    want = {i: (2 if i in _TARGETS else 1) for i in range(_N)}
    want[_SENTINEL] = 1
    assert tally == want, (
        f'per-message delivery tally is {dict(sorted(tally.items()))!r}, expected '
        f'{dict(sorted(want.items()))!r} -- the reported items must be redelivered exactly once '
        f'and every unreported item must never be delivered again'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
