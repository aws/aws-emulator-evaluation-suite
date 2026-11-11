"""50-distinct-code-artifacts-no-shared-code-store."""
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

CHECK = "50-distinct-code-artifacts-no-shared-code-store"
GROUP = 'concurrency'
SERVICES = ['lambda']

_N = 50
_NODE_FROM = 45           # functions 45..49 are nodejs22.x; 0..44 are python3.12
_CREATE_WORKERS = 10      # control plane; the invoke fan-out below is the full 50
_PROPAGATION_DEADLINE_S = 120.0
_CREATE_DEADLINE_S = 180.0
_LOG_DEADLINE_S = 180.0
_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_BASIC_EXEC = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'


def _zip(name: str, source: str) -> bytes:
    """A deterministic one-entry zip built in memory -- no toolchain, no external artifact."""
    buf = io.BytesIO()
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.external_attr = 0o644 << 16
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(info, source)
    return buf.getvalue()


def _drain_log_groups(logs, prefix: str, deadline_s: float = 120.0, quiet_rounds: int = 3) -> None:
    """Delete every log group under *prefix*, then keep deleting until *quiet_rounds* listings are empty.

    Lambda creates a log group asynchronously on first invocation, so one delete can lose the race.
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


def _absent_ok(fn) -> None:
    """Run a teardown delete, treating an already-deleted resource as done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Fifty concurrently created functions (45 python3.12, 5 nodejs22.x) from distinct zips report
    their own CodeSha256, return their own secret and log only their own RequestId; breaking one
    function's code leaves its siblings intact, and all fifty are gone after deletion.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html
    """
    cfg = Config(max_pool_connections=_N + 16, retries={'mode': 'standard', 'max_attempts': 5})
    lam = ctx.client('lambda', config=cfg)
    iam = ctx.client('iam', config=cfg)
    logs = ctx.client('logs', config=cfg)

    # ---- one shared execution role: IAM propagation is then paid once, not fifty times ----
    role_name = ctx.unique_name('sim2real-behav-d1-lamrole-')
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST,
                               Description='sim2real d1 scale fan-out',
                               Tags=[{'Key': 'sim2real', 'Value': 'd1-scale-fanout'}])['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC))

    stem = role_name.replace('lamrole-', '')

    specs = []
    for i in range(_N):
        secret = uuid.uuid4().hex
        if i >= _NODE_FROM:
            src = ('export const handler = async () => '
                   f'({{ secret: "{secret}", idx: {i} }});\n')
            blob, runtime = _zip('index.mjs', src), 'nodejs22.x'
        else:
            src = ('def handler(event, context):\n'
                   f'    return {{"secret": "{secret}", "idx": {i}}}\n')
            blob, runtime = _zip('index.py', src), 'python3.12'
        specs.append({'i': i, 'name': f'{stem}-fn{i:02d}',
                      'secret': secret, 'zip': blob, 'runtime': runtime,
                      'sha': base64.b64encode(hashlib.sha256(blob).digest()).decode()})
    assert len({s['secret'] for s in specs}) == _N, 'the generated secrets are not distinct'
    assert len({s['sha'] for s in specs}) == _N, 'the generated zips are not distinct'

    def _create(spec: dict, publish_cleanup: bool = True):
        deadline = time.time() + _CREATE_DEADLINE_S
        attempt = 0
        while True:
            try:
                resp = lam.create_function(
                    FunctionName=spec['name'], Runtime=spec['runtime'], Role=role_arn,
                    Handler='index.handler', Code={'ZipFile': spec['zip']},
                    MemorySize=128, Timeout=10, Publish=False,
                    Tags={'sim2real': 'd1-scale-fanout'},
                )
                if publish_cleanup:
                    name = spec['name']
                    # The body deletes these itself; these nets only catch an early failure.
                    ctx.on_cleanup(lambda n=name: _absent_ok(
                        lambda: lam.delete_function(FunctionName=n)))
                    ctx.on_cleanup(lambda n=name: _absent_ok(
                        lambda: logs.delete_log_group(logGroupName=f'/aws/lambda/{n}')))
                return resp
            except ClientError as exc:
                code = exc.response.get('Error', {}).get('Code')
                msg = exc.response.get('Error', {}).get('Message', '')
                retryable = (code == 'TooManyRequestsException'
                             or (code == 'InvalidParameterValueException'
                                 and 'cannot be assumed' in msg))
                assert retryable and time.time() < deadline, (
                    f'CreateFunction for {spec["name"]!r} failed with {code!r}: {msg!r}'
                )
                attempt += 1
                time.sleep(min(3.0, 0.5 + 0.25 * attempt))

    # ---- propagation barrier on a throwaway function: the role must be assumable ----
    # IAM exposes no condition to poll, so _create retries the "cannot be assumed" refusal, bounded.
    barrier = {**specs[0], 'name': f'{stem}-barrier'}
    started = time.time()
    _create(barrier, publish_cleanup=False)
    lam.delete_function(FunctionName=barrier['name'])
    try:
        logs.delete_log_group(logGroupName=f'/aws/lambda/{barrier["name"]}')
    except ClientError:
        pass
    assert time.time() - started < _PROPAGATION_DEADLINE_S, (
        f'the execution role was still unassumable after '
        f'{time.time() - started:.0f}s'
    )

    # ---- (1)(2) fifty concurrent CreateFunction calls ----
    with ThreadPoolExecutor(max_workers=_CREATE_WORKERS) as pool:
        created = list(pool.map(_create, specs))

    arns = [r['FunctionArn'] for r in created]
    assert len(set(arns)) == _N, (
        f'{_N!r} CreateFunction calls returned only {len(set(arns))!r} distinct FunctionArns'
    )
    for spec, resp in zip(specs, created):
        assert resp['FunctionArn'].endswith(':' + spec['name']), (
            f'{spec["name"]!r} was given the arn {resp["FunctionArn"]!r}'
        )
        assert resp['CodeSha256'] == spec['sha'], (
            f'{spec["name"]!r} reports CodeSha256 {resp["CodeSha256"]!r} but the zip this check '
            f'uploaded hashes to {spec["sha"]!r} -- the code store does not hold this '
            f'function\'s own artifact'
        )
    assert len({r['CodeSha256'] for r in created}) == _N, (
        f'the {_N!r} functions report only '
        f'{len({r["CodeSha256"] for r in created})!r} distinct CodeSha256 values -- one shared '
        f'code store'
    )

    with ThreadPoolExecutor(max_workers=_CREATE_WORKERS) as pool:
        list(pool.map(lambda s: lam.get_waiter('function_active_v2').wait(
            FunctionName=s['name'],
            WaiterConfig={"Delay": 2, "MaxAttempts": 150}), specs))

    # ---- (3)(4)(5)(6)(7) fifty concurrent invocations ----
    def _invoke(spec: dict) -> dict:
        resp = lam.invoke(FunctionName=spec['name'], InvocationType='RequestResponse')
        return {'i': spec['i'], 'status': resp['StatusCode'],
                'error': resp.get('FunctionError'),
                'payload': resp['Payload'].read().decode(),
                'request_id': resp['ResponseMetadata']['RequestId']}

    with ThreadPoolExecutor(max_workers=_N) as pool:
        invocations = list(pool.map(_invoke, specs))

    broken = [(o['i'], o['status'], o['error']) for o in invocations
              if o['status'] != 200 or o['error'] is not None]
    assert broken == [], f'invocations that did not return a clean 200: {broken!r}'

    read_map, idx_map = {}, {}
    for obs in invocations:
        body = json.loads(obs['payload'])
        read_map[obs['i']] = body['secret']
        idx_map[obs['i']] = body['idx']
    written = {s['i']: s['secret'] for s in specs}
    assert read_map == written, (
        'a function returned a secret that is not the one embedded in its own zip: '
        + repr({i: (written[i], read_map.get(i)) for i in written if read_map.get(i) != written[i]})
    )
    assert idx_map == {i: i for i in range(_N)}, (
        'the idx a function returned is not its own: '
        + repr({i: v for i, v in idx_map.items() if v != i})
    )
    node_ids = list(range(_NODE_FROM, _N))
    assert {i: read_map[i] for i in node_ids} == {i: written[i] for i in node_ids}, (
        f'the nodejs22.x functions did not return their own secrets -- the code store is '
        f'runtime-collapsed: {[i for i in node_ids if read_map[i] != written[i]]!r}'
    )
    assert len(set(o['request_id'] for o in invocations)) == _N, (
        f'the {_N!r} invocations share request ids: '
        f'{len(set(o["request_id"] for o in invocations))!r} distinct'
    )

    # ---- (8) log-plane isolation, polled to a hard deadline: Logs ingestion is not immediate ----
    rid = {o['i']: o['request_id'] for o in invocations}
    all_rids = set(rid.values())

    def _group_text(i: int) -> str:
        try:
            pager = logs.get_paginator('filter_log_events').paginate(
                logGroupName=f'/aws/lambda/{specs[i]["name"]}')
            return '\n'.join(e['message'] for page in pager for e in page.get('events', []))
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return ''
            raise

    deadline = time.time() + _LOG_DEADLINE_S
    pending = set(range(_N))
    texts: dict[int, str] = {}
    while True:
        with ThreadPoolExecutor(max_workers=_N) as pool:
            for i, text in zip(sorted(pending), pool.map(_group_text, sorted(pending))):
                texts[i] = text
        pending = {i for i in pending if rid[i] not in texts[i]}
        if not pending:
            break
        assert time.time() < deadline, (
            f'{len(pending)!r} of {_N!r} log groups never carried their own invocation\'s '
            f'RequestId within {_LOG_DEADLINE_S!r}s: {sorted(pending)!r}'
        )
        time.sleep(4.0)

    for i in range(_N):
        foreign = sorted(r for r in all_rids - {rid[i]} if r in texts[i])
        assert foreign == [], (
            f'/aws/lambda/{specs[i]["name"]} carries {len(foreign)!r} RequestId(s) belonging to '
            f'other functions\' invocations: {foreign[:3]!r}'
        )

    # ---- (9) failure arm: one function's bad code must not poison the shared store ----
    bad = _zip('index.py',
               'def handler(event, context):\n    raise RuntimeError("sim2real-d1-boom")\n')
    bad_sha = base64.b64encode(hashlib.sha256(bad).digest()).decode()
    updated = lam.update_function_code(FunctionName=specs[0]['name'], ZipFile=bad)
    assert updated['CodeSha256'] == bad_sha, (
        f'UpdateFunctionCode reports CodeSha256 {updated["CodeSha256"]!r}, expected {bad_sha!r}'
    )
    lam.get_waiter('function_updated_v2').wait(FunctionName=specs[0]['name'], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    failed = lam.invoke(FunctionName=specs[0]['name'], InvocationType='RequestResponse')
    assert failed['StatusCode'] == 200, (
        f'a handler that raises returned StatusCode {failed["StatusCode"]!r}, expected 200 with a '
        f'FunctionError'
    )
    assert failed.get('FunctionError') == 'Unhandled', (
        f'FunctionError was {failed.get("FunctionError")!r}, expected "Unhandled"'
    )
    err = json.loads(failed['Payload'].read().decode())
    assert err.get('errorType') == 'RuntimeError', (
        f'the error payload reports errorType {err.get("errorType")!r}, expected "RuntimeError"; '
        f'payload was {err!r}'
    )
    message = err.get('errorMessage')
    assert message == 'sim2real-d1-boom', f'the error payload reports errorMessage {message!r}'

    controls = [1, _N - 1]
    with ThreadPoolExecutor(max_workers=len(controls)) as pool:
        again = list(pool.map(lambda i: _invoke(specs[i]), controls))
    for i, obs in zip(controls, again):
        assert obs['error'] is None, (
            f'function {i!r} reports FunctionError {obs["error"]!r} after a SIBLING function\'s '
            f'code was replaced with a raising handler'
        )
        assert json.loads(obs['payload'])['secret'] == written[i], (
            f'function {i!r} returned {json.loads(obs["payload"])!r} after a sibling\'s code was '
            f'replaced -- one function\'s update reached another\'s code'
        )
    survivors = lam.get_function(FunctionName=specs[1]['name'])['Configuration']['CodeSha256']
    assert survivors == specs[1]['sha'], (
        f'function 1 now reports CodeSha256 {survivors!r}, expected its own {specs[1]["sha"]!r}'
    )

    # ---- the control re-invocations' log delivery has not settled yet; waiting for it keeps it
    # from racing the delete-and-drain below and recreating these two log groups.
    control_rid = {i: obs['request_id'] for i, obs in zip(controls, again)}
    pending_controls = set(controls)
    deadline = time.time() + _LOG_DEADLINE_S
    while pending_controls:
        for i in list(pending_controls):
            if control_rid[i] in _group_text(i):
                pending_controls.discard(i)
        if not pending_controls:
            break
        assert time.time() < deadline, (
            f'the control invocation(s) for {sorted(pending_controls)!r} never appeared in their '
            f'own log group within {_LOG_DEADLINE_S!r}s of being invoked'
        )
        time.sleep(4.0)

    # ---- (10) residual: delete the fan-out and assert it is gone from a paginated listing ----
    def _delete(spec: dict) -> str | None:
        try:
            lam.delete_function(FunctionName=spec['name'])
            return None
        except ClientError as exc:
            return f'{spec["name"]}: {exc.response.get("Error", {}).get("Code")}'

    with ThreadPoolExecutor(max_workers=_CREATE_WORKERS) as pool:
        undeleted = [e for e in pool.map(_delete, specs) if e is not None]
    assert undeleted == [], f'DeleteFunction failed for: {undeleted!r}'

    def _gone(spec: dict) -> str | None:
        try:
            lam.get_function(FunctionName=spec['name'])
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return None
            return f'{spec["name"]}: {code}'
        return f'{spec["name"]}: still present'

    with ThreadPoolExecutor(max_workers=_CREATE_WORKERS) as pool:
        residual = [e for e in pool.map(_gone, specs) if e is not None]
    assert residual == [], f'GetFunction after DeleteFunction: {residual!r}'

    listed = {f['FunctionName']
              for page in lam.get_paginator('list_functions').paginate()
              for f in page['Functions']}
    still = sorted(listed & {s['name'] for s in specs})
    assert still == [], f'ListFunctions still lists deleted functions: {still!r}'

    _drain_log_groups(logs, f'/aws/lambda/{stem}')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
