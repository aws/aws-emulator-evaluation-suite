"""duplicate-create-function-rejected-leaves-every-sibling-code-artifact-intact."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-create-function-rejected-leaves-every-sibling-code-artifact-intact"
GROUP = 'concurrency'
SERVICES = ['lambda']

_N = 8
_CREATE_DEADLINE_S = 180.0
_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_BASIC_EXEC = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'


def _zip(source: str) -> bytes:
    """A deterministic one-entry zip built in memory."""
    buf = io.BytesIO()
    info = zipfile.ZipInfo('index.py', date_time=(1980, 1, 1, 0, 0, 0))
    info.external_attr = 0o644 << 16
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(info, source)
    return buf.getvalue()


def _handler_zip(secret: str, idx: int) -> bytes:
    return _zip('def handler(event, context):\n'
                f'    return {{"secret": "{secret}", "idx": {idx}}}\n')


def _client_error(fn):
    """Call fn() and return (Error.Code, Error.Message) of the ClientError it raises.

    Raises if fn() succeeds: a CreateFunction accepted on an existing name is the defect itself.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message', '')
    raise AssertionError('CreateFunction succeeded on a name that already exists')


def _gone_ok(delete) -> None:
    """Teardown delete that tolerates a resource the body already removed."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


def _drain_log_groups(logs, prefix: str, deadline_s: float = 120.0, quiet_rounds: int = 3) -> None:
    """Delete every log group under *prefix* until *quiet_rounds* consecutive listings are empty.

    Lambda creates log groups asynchronously after invocation, so a single delete can lose the race.
    """
    deadline = time.time() + deadline_s
    quiet = 0
    while quiet < quiet_rounds:
        found = [g['logGroupName']
                 for page in logs.get_paginator('describe_log_groups').paginate(
                     logGroupNamePrefix=prefix)
                 for g in page['logGroups']]
        if not found:
            quiet += 1
            time.sleep(2.0)
            continue
        quiet = 0
        for name in found:
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
                    raise
        assert time.time() < deadline, (
            f'log groups under {prefix!r} kept reappearing for {deadline_s!r}s after every '
            f'function was deleted; last seen {found!r}'
        )
    remaining = [g['logGroupName']
                 for page in logs.get_paginator('describe_log_groups').paginate(
                     logGroupNamePrefix=prefix)
                 for g in page['logGroups']]
    assert remaining == [], f'log groups survived this check: {remaining!r}'


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Concurrent duplicate CreateFunction calls with different code all fail with
    ResourceConflictException and replace no artifact: CodeSha256 and invoked output are unchanged,
    while the same new zip under a fresh name creates and runs, proving the name caused the refusal.
    """
    cfg = Config(max_pool_connections=_N + 16, retries={'mode': 'standard', 'max_attempts': 5})
    lam = ctx.client('lambda', config=cfg)
    iam = ctx.client('iam', config=cfg)
    logs = ctx.client('logs', config=cfg)

    role_name = ctx.unique_name('sim2real-behav-d1-duprole-')
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST,
                               Description='sim2real d1 duplicate-create negative')['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC))

    stem = role_name.replace('duprole-', '')

    def _create(name: str, blob: bytes, register: bool = True):
        deadline = time.time() + _CREATE_DEADLINE_S
        attempt = 0
        while True:
            try:
                resp = lam.create_function(
                    FunctionName=name, Runtime='python3.12', Role=role_arn,
                    Handler='index.handler', Code={'ZipFile': blob},
                    MemorySize=128, Timeout=10, Publish=False,
                    Tags={'sim2real': 'd1-duplicate-create'},
                )
                if register:
                    ctx.on_cleanup(lambda n=name: _gone_ok(
                        lambda: lam.delete_function(FunctionName=n)))
                    ctx.on_cleanup(lambda n=name: _gone_ok(
                        lambda: logs.delete_log_group(logGroupName=f'/aws/lambda/{n}')))
                return resp
            except ClientError as exc:
                code = exc.response.get('Error', {}).get('Code')
                msg = exc.response.get('Error', {}).get('Message', '')
                retryable = (code == 'TooManyRequestsException'
                             or (code == 'InvalidParameterValueException'
                                 and 'cannot be assumed' in msg))
                assert retryable and time.time() < deadline, (
                    f'CreateFunction for {name!r} failed with {code!r}: {msg!r}'
                )
                attempt += 1
                time.sleep(min(3.0, 0.5 + 0.25 * attempt))

    # ---- setup: eight functions, eight distinct first-generation artifacts ----
    gen1 = []
    for i in range(_N):
        secret = uuid.uuid4().hex
        blob = _handler_zip(secret, i)
        gen1.append({'i': i, 'name': f'{stem}-fn{i:02d}', 'secret': secret, 'zip': blob,
                     'sha': base64.b64encode(hashlib.sha256(blob).digest()).decode()})

    with ThreadPoolExecutor(max_workers=_N) as pool:
        created = list(pool.map(lambda s: _create(s['name'], s['zip']), gen1))
    for spec, resp in zip(gen1, created):
        assert resp['CodeSha256'] == spec['sha'], (
            f'{spec["name"]!r} reports CodeSha256 {resp["CodeSha256"]!r}, expected {spec["sha"]!r}'
        )
    with ThreadPoolExecutor(max_workers=_N) as pool:
        list(pool.map(lambda s: lam.get_waiter('function_active_v2').wait(
            FunctionName=s['name'],
            WaiterConfig={"Delay": 2, "MaxAttempts": 150}), gen1))

    def _secret_of(name: str) -> tuple[str, str | None]:
        resp = lam.invoke(FunctionName=name, InvocationType='RequestResponse')
        body = json.loads(resp['Payload'].read().decode())
        return body.get('secret'), resp.get('FunctionError')

    with ThreadPoolExecutor(max_workers=_N) as pool:
        before = dict(zip([s['name'] for s in gen1],
                          pool.map(lambda s: _secret_of(s['name']), gen1)))
    assert before == {s['name']: (s['secret'], None) for s in gen1}, (
        'the setup functions do not each execute their own artifact: ' + repr(before)
    )

    # Only the zip differs; every other argument stays valid.
    gen2 = []
    for spec in gen1:
        secret = uuid.uuid4().hex
        blob = _handler_zip(secret, 100 + spec['i'])
        gen2.append({'i': spec['i'], 'name': spec['name'], 'secret': secret, 'zip': blob,
                     'sha': base64.b64encode(hashlib.sha256(blob).digest()).decode()})
    assert {s['sha'] for s in gen2}.isdisjoint({s['sha'] for s in gen1}), (
        'the second-generation zips are not distinct from the first'
    )

    with ThreadPoolExecutor(max_workers=_N) as pool:
        errors = list(pool.map(
            lambda s: _client_error(lambda: lam.create_function(
                FunctionName=s['name'], Runtime='python3.12', Role=role_arn,
                Handler='index.handler', Code={'ZipFile': s['zip']},
                MemorySize=128, Timeout=10, Publish=False)), gen2))
    codes = [code for code, _ in errors]
    assert codes == ['ResourceConflictException'] * _N, (
        f'{_N!r} concurrent CreateFunction calls on names that already exist returned {codes!r}, '
        f'expected ResourceConflictException for every one'
    )
    messages = [msg for _, msg in errors]
    assert messages == [f'Function already exist: {s["name"]}' for s in gen2], (
        f'duplicate CreateFunction messages: {messages!r}'
    )

    # ---- effect ABSENT: control plane ----
    with ThreadPoolExecutor(max_workers=_N) as pool:
        shas = dict(zip([s['name'] for s in gen1], pool.map(
            lambda s: lam.get_function(
                FunctionName=s['name'])['Configuration']['CodeSha256'], gen1)))
    assert shas == {s['name']: s['sha'] for s in gen1}, (
        'a rejected CreateFunction replaced the stored code artifact: '
        + repr({s['name']: (s['sha'], shas[s['name']], s2['sha'])
                for s, s2 in zip(gen1, gen2) if shas[s['name']] != s['sha']})
    )

    # ---- effect ABSENT: data plane -- the ORIGINAL code is still what runs ----
    with ThreadPoolExecutor(max_workers=_N) as pool:
        after = dict(zip([s['name'] for s in gen1],
                         pool.map(lambda s: _secret_of(s['name']), gen1)))
    assert after == {s['name']: (s['secret'], None) for s in gen1}, (
        'a rejected CreateFunction changed the code that actually EXECUTES: '
        + repr({s['name']: {'expected': s['secret'], 'observed': after[s['name']],
                            'gen2_secret': s2['secret']}
                for s, s2 in zip(gen1, gen2) if after[s['name']] != (s['secret'], None)})
    )
    leaked = [s2['secret'] for s2 in gen2 if (s2['secret'], None) in after.values()]
    assert leaked == [], (
        f'a second-generation secret from a REJECTED CreateFunction is being returned by a live '
        f'function: {leaked!r}'
    )

    # ---- positive control: the same gen2 artifact under a FRESH name ----
    control = gen2[0]
    fresh = f'{stem}-control'
    resp = _create(fresh, control['zip'])
    assert resp['CodeSha256'] == control['sha'], (
        f'the control function reports CodeSha256 {resp["CodeSha256"]!r}, expected '
        f'{control["sha"]!r} -- the artifact the eight rejections carried'
    )
    lam.get_waiter('function_active_v2').wait(FunctionName=fresh, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    got, err = _secret_of(fresh)
    assert err is None, f'the control function raised: {err!r}'
    assert got == control['secret'], (
        f'the control function returned {got!r}, expected the second-generation secret '
        f'{control["secret"]!r} -- so the eight rejections above cannot be attributed to the name '
        f'collision'
    )

    # Deleted and drained here: Lambda creates log groups asynchronously, so a delete registered
    # at create time loses the race (see _drain_log_groups).
    names = [s['name'] for s in gen1] + [fresh]
    with ThreadPoolExecutor(max_workers=_N) as pool:
        list(pool.map(lambda n: lam.delete_function(FunctionName=n), names))
    _drain_log_groups(logs, f'/aws/lambda/{stem}')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
