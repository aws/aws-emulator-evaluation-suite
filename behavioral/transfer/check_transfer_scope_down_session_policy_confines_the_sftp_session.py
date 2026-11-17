"""transfer-scope-down-session-policy-confines-the-sftp-session."""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "transfer-scope-down-session-policy-confines-the-sftp-session"
GROUP = 'sftp-rejection'
SERVICES = ['transfer']

# Server provisioning dominates: one server plus its SFTP sessions takes several minutes end to
# end, so these deadlines bound each provisioning and propagation wait.
_ONLINE_TIMEOUT_S = 900.0
_ENDPOINT_TIMEOUT_S = 420.0
_GONE_TIMEOUT_S = 45.0
_PROPAGATION_TIMEOUT_S = 180.0
_INTERVAL_S = 15.0

# Carried in a failure detail when the server host accepts no SSH connection, so a missing SFTP
# data plane reads as a failed check rather than as a client connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_SEQ = itertools.count()

_OWN = b'sim2real own-prefix payload \x00\xff\n' * 96
_INTRUDER = b'sim2real other-prefix payload \x00\xfe\n' * 96

# ===== helpers =====
#
# The sftp and ssh-keygen binaries are invoked by absolute path; run() declares them with
# require_tools, so a runner without them reports tool_missing.
def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Bounded retry with a deadline that RAISES on exhaustion. Never returns its last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observation: {last!r}")
        time.sleep(interval_s)


def _retry_on_iam_propagation(fn, *, attempts=10, delay_s=8.0):
    """CreateUser fails until the freshly created role is assumable by Transfer.

    IAM exposes no condition to poll for "this role is now assumable", so the bounded retry on
    the propagation codes IS the wait; there is no fixed sleep standing in for it. Exhaustion
    raises.
    """
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code in ('AccessDeniedException', 'InvalidRequestException'):
                last = exc
                time.sleep(delay_s)
                continue
            raise
    raise AssertionError(f"role never became assumable by transfer.amazonaws.com: {last!r}")


def _workdir(ctx) -> str:
    """A private scratch dir for this run. Never a fixed /tmp path: the harness host is shared,
    and a predictable name lets one run overwrite another's private key."""
    path = tempfile.mkdtemp(prefix='sim2real-transfer-')
    ctx.on_cleanup(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


def _keygen(workdir: str, stem: str = 'sim2real-key', *, kind: str = 'rsa', bits: str = '3072'):
    """Generate a keypair with the real ssh-keygen. Returns (private path, public body).

    -m PEM is load-bearing: Transfer's Secrets Manager / HostKey formats want PKCS#1 PEM, and
    OpenSSH 9.x defaults to its own container format instead.
    """
    priv = os.path.join(workdir, stem)
    argv = ['/usr/bin/ssh-keygen', '-q', '-t', kind]
    if kind == 'rsa':
        # -m PEM is load-bearing for RSA: Transfer's HostKey / connector formats want PKCS#1 PEM
        # and OpenSSH 9.x defaults to its own container instead. ed25519 has no PKCS#1 form, so
        # -m PEM is omitted there rather than passed and ignored.
        argv += ['-b', bits, '-m', 'PEM']
    argv += ['-N', '', '-C', 'sim2real', '-f', priv]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        f"ssh-keygen -t {kind} failed with rc {proc.returncode!r}: "
        f"{proc.stdout!r} {proc.stderr!r}")
    os.chmod(priv, 0o600)
    return priv, open(priv + '.pub').read().strip()


def _sftp(ctx, workdir: str, host: str, user: str, priv: str, lines, *,
          timeout_s=300.0, extra=()):
    """One non-interactive session through /usr/bin/sftp -- the real OpenSSH client.

    BatchMode + NumberOfPasswordPrompts=0 are load-bearing: without them a refused publickey
    auth blocks on a password prompt until the subprocess timeout, turning a clean refusal into
    a hang. UserKnownHostsFile=/dev/null keeps the shared host's ~/.ssh out of the run.
    """
    batch = os.path.join(workdir, f'batch-{next(_SEQ)}.sftp')
    with open(batch, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    argv = ['/usr/bin/sftp', '-b', batch, '-i', priv,
            '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'BatchMode=yes',
            '-o', 'NumberOfPasswordPrompts=0',
            '-o', 'PreferredAuthentications=publickey',
            '-o', 'ConnectTimeout=30',
            *extra, f'{user}@{host}']
    socket.getaddrinfo(host, 22)  # customer-built AWS host
    proc = subprocess.run(argv, env=ctx.subprocess_env(), cwd=workdir,  # customer-built AWS host
                          capture_output=True, text=True, timeout=timeout_s)
    return proc.returncode, proc.stdout, proc.stderr


def _wait_for_ssh_banner(host: str, *, timeout_s, interval_s=10.0) -> bytes:
    """Poll TCP 22 until the server sends an SSH identification string.

    DescribeServer reporting ONLINE is the control plane's claim; the banner is the only
    evidence the endpoint actually terminates SSH. Exhaustion is a data-plane FAIL, never a
    skip -- "provisioned but unconnectable" is the defect, not the environment.
    """
    deadline = time.monotonic() + timeout_s
    last = 'never attempted'
    while True:
        try:
            sock = socket.create_connection((host, 22), timeout=20.0)  # customer-built AWS host
            try:
                sock.settimeout(20.0)
                banner = sock.recv(255)
            finally:
                sock.close()
            if banner.startswith(b'SSH-2.0-'):
                return banner
            last = f'banner {banner!r}'
        except OSError as exc:
            last = f'{type(exc).__name__}: {exc}'
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: {host}:22 never spoke SSH within {timeout_s}s "
                f"although DescribeServer reported ONLINE; last attempt: {last}")
        time.sleep(interval_s)


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name('sim2real-transfer-dp-').lower().replace('_', '-')
    if ctx.region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={'LocationConstraint': ctx.region})

    def _drop() -> None:
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket):
            objs = [{'Key': o['Key']} for o in page.get('Contents', [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={'Objects': objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_drop)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})
    return bucket


def _create_transfer_role(ctx, iam, statements) -> str:
    """A role Transfer can assume, created in-check. NOT the shared `_role_arn` helper: that one
    hands real AWS an ambient role and every other target a fabricated ARN (see the bar's
    "Escalate, don't inline"), which would make this check's IAM leg untestable."""
    role = ctx.unique_name('sim2real-transfer-dp-role-')
    trust = {'Version': '2012-10-17',
             'Statement': [{'Effect': 'Allow',
                            'Principal': {'Service': 'transfer.amazonaws.com'},
                            'Action': 'sts:AssumeRole'}]}
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust),
                          Description=f'sim2real {CHECK}',
                          Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']

    def _drop() -> None:
        try:
            iam.delete_role_policy(RoleName=role, PolicyName='sim2real-inline')
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role)

    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=role, PolicyName='sim2real-inline',
                        PolicyDocument=json.dumps({'Version': '2012-10-17',
                                                   'Statement': statements}))
    return arn


def _home_policy(bucket: str):
    """Deliberately the WHOLE bucket. Where the check asserts a boundary, the IAM role must not be
    that boundary, or the check would be asserting the wrong subject."""
    return [
        {'Effect': 'Allow', 'Action': ['s3:ListBucket', 's3:GetBucketLocation'],
         'Resource': f'arn:aws:s3:::{bucket}'},
        {'Effect': 'Allow',
         'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:GetObjectVersion',
                    's3:GetObjectACL', 's3:PutObjectACL'],
         'Resource': f'arn:aws:s3:::{bucket}/*'},
    ]


def _create_server(ctx, transfer, **kwargs) -> str:
    server_id = transfer.create_server(
        EndpointType='PUBLIC', IdentityProviderType='SERVICE_MANAGED', Protocols=['SFTP'],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}], **kwargs)['ServerId']

    def _drop() -> None:
        # DeleteServer is the ONLY call that stops the ~$0.30/endpoint-hour meter -- StopServer
        # does not -- so it is issued FIRST and verified after.
        #
        # The verify deadline is deliberately SHORT. Cleanups run LIFO
        # (simparity.behavioral.context.Context.run_cleanups pops) under a hard 60s wrapper
        # (DEFAULT_CLEANUP_TIMEOUT_S), so a slow DeleteServer must not eat the whole budget and
        # leave the IAM role and S3 bucket registered EARLIER untorn.
        transfer.delete_server(ServerId=server_id)
        _poll(lambda: _describe_state(transfer, server_id), lambda s: s == 'GONE',
              timeout_s=_GONE_TIMEOUT_S, interval_s=5.0,
              what=f'server {server_id} to disappear after DeleteServer')

    ctx.on_cleanup(_drop)
    return server_id


def _describe_state(transfer, server_id: str) -> str:
    try:
        return transfer.describe_server(ServerId=server_id)['Server']['State']
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
            return 'GONE'
        raise


def _online(ctx, transfer, server_id: str) -> dict:
    return _poll(lambda: transfer.describe_server(ServerId=server_id)['Server'],
                 lambda srv: srv['State'] == 'ONLINE',
                 timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
                 what=f'server {server_id} to reach ONLINE')


def _all_keys(s3, bucket: str, prefix: str = '') -> set:
    """Every key in the bucket, fully paginated. The sandbox accounts are a shared pool and a
    membership assertion off page one is a latent flake, not a fidelity signal."""
    keys = set()
    for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
        keys.update(o['Key'] for o in page.get('Contents', []))
    return keys


def _sftp_names(stdout: str) -> set:
    """Names from an sftp `ls`, with the client's own echoed prompt lines removed.

    Parsed structurally rather than by slicing the blob: `sftp -b` echoes every command it runs as
    a `sftp> ...` line into the same stream as the listing, and a naive split would report `sftp`
    and `ls` as directory entries.
    """
    names = set()
    for line in stdout.splitlines():
        if line.startswith('sftp>') or not line.strip():
            continue
        names.update(tok.lstrip('/') for tok in line.split() if tok.strip())
    return names


def _host(ctx, server_id: str) -> str:
    """The server's public SFTP hostname. No region literal: ctx.region."""
    return f'{server_id}.server.transfer.{ctx.region}.amazonaws.com'


def _scope_down_policy(bucket: str) -> str:
    """The documented scope-down session policy: the user may only touch
    `home/${transfer:UserName}/`. The bucket is named literally rather than via
    ${transfer:HomeBucket} for the ListBucket resource so that a target which fails to resolve the
    variable cannot accidentally widen the policy to every bucket."""
    return json.dumps({
        'Version': '2012-10-17',
        'Statement': [
            {'Sid': 'AllowListingOfUserFolder',
             'Effect': 'Allow',
             'Action': ['s3:ListBucket'],
             'Resource': [f'arn:aws:s3:::{bucket}'],
             'Condition': {'StringLike': {'s3:prefix': [
                 'home/${transfer:UserName}/*', 'home/${transfer:UserName}']}}},
            {'Sid': 'HomeDirObjectAccess',
             'Effect': 'Allow',
             'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:GetObjectVersion',
                        's3:GetObjectTagging'],
             'Resource': [f'arn:aws:s3:::{bucket}/home/${{transfer:UserName}}/*']},
        ],
    })


def _permissive_policy(bucket: str) -> str:
    """The restore leg: identical in every way except that the Resource is the whole bucket. The
    ONLY thing that changes between the refusal and the restore is this document."""
    return json.dumps({
        'Version': '2012-10-17',
        'Statement': [
            {'Sid': 'AllowListingOfUserFolder',
             'Effect': 'Allow',
             'Action': ['s3:ListBucket'],
             'Resource': [f'arn:aws:s3:::{bucket}']},
            {'Sid': 'HomeDirObjectAccess',
             'Effect': 'Allow',
             'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:GetObjectVersion',
                        's3:GetObjectTagging'],
             'Resource': [f'arn:aws:s3:::{bucket}/*']},
        ],
    })


def _assert_refused(rc: int, err: str, workdir: str, local: str, *, what: str) -> None:
    """A refused get: non-zero exit, a diagnostic naming the path, and NO local file.

    Deliberately not pinned to a stderr literal, whose wording is the client's. It is still unsatisfiable by a target that
    silently succeeds, because the local file must not exist and the caller pairs every call here
    with a positive control on the same wiring.
    """
    assert rc != 0, (
        f"{what}: sftp exited 0, so the scope-down policy did not refuse the transfer; "
        f"stderr {err[-400:]!r}")
    assert err.strip(), (
        f"{what}: sftp failed with rc {rc!r} and an EMPTY stderr, so there is no evidence the "
        f"server refused anything rather than the client dying locally")
    path = os.path.join(workdir, local)
    assert not os.path.exists(path), (
        f"{what}: the refused get still wrote {local!r} ({os.path.getsize(path)!r} bytes), so the "
        f"transfer happened despite rc {rc!r}")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A scope-down session Policy confines a live SFTP session: the user is refused another user's
    prefix by relative and absolute path with that object unmodified, while a twin user with the
    same role reads it, and widening the user's own policy makes the identical get succeed.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    # The account is read, never hardcoded; it also proves the leased-credential path is live
    # before anything is provisioned.
    account = ctx.client('sts').get_caller_identity()['Account']
    assert account.isdigit() and len(account) == 12, (
        f"GetCallerIdentity returned a malformed account id {account!r}")

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)

    # Names first: the seeded keys must match ${transfer:UserName} exactly.
    confined = ctx.unique_name('sim2real-confined-u-').replace('_', '-').lower()
    twin = ctx.unique_name('sim2real-twin-u-').replace('_', '-').lower()
    assert confined != twin, "the two usernames collided"

    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=f'home/{confined}/own.txt', Body=_OWN)
    s3.put_object(Bucket=bucket, Key=f'home/{twin}/secret.txt', Body=_INTRUDER)
    intruder_before = s3.head_object(Bucket=bucket, Key=f'home/{twin}/secret.txt')

    # The WHOLE bucket, on purpose (see _home_policy): if the role were scoped, IAM and not the
    # session policy could be what refuses, and this check would assert the wrong subject.
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer)
    _online(ctx, transfer, server_id)

    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=confined, Role=role_arn,
        HomeDirectory=f'/{bucket}/home/{confined}', HomeDirectoryType='PATH',
        Policy=_scope_down_policy(bucket),
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=confined))

    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=twin, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        Policy=_permissive_policy(bucket),
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=twin))

    host = _host(ctx, server_id)
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    # ---- POSITIVE CONTROL FIRST. Also the propagation barrier: until a permitted transfer really
    # works, a refusal is indistinguishable from a user or an endpoint that is not ready yet.
    ok_rc, _, ok_err = _sftp(ctx, workdir, host, confined, priv,
                             ['get own.txt inside.bin', 'quit'])
    assert ok_rc == 0, (
        f"the get INSIDE the confined user's own prefix failed, so nothing below can be "
        f"attributed to the policy: rc {ok_rc!r}, stderr {ok_err[-600:]!r}")
    inside = open(os.path.join(workdir, 'inside.bin'), 'rb').read()
    assert inside == _OWN, (
        f"the permitted get returned {len(inside)!r} bytes with sha256 "
        f"{hashlib.sha256(inside).hexdigest()!r}, expected {len(_OWN)!r} bytes with sha256 "
        f"{hashlib.sha256(_OWN).hexdigest()!r}")

    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_OWN)
    put_rc, _, put_err = _sftp(ctx, workdir, host, confined, priv,
                               [f'put {local_up} uploaded.bin', 'quit'])
    assert put_rc == 0, (
        f"the put INSIDE the confined user's own prefix failed: rc {put_rc!r}, "
        f"stderr {put_err[-600:]!r}")
    landed = s3.get_object(Bucket=bucket, Key=f'home/{confined}/uploaded.bin')['Body'].read()
    assert landed == _OWN, (
        f"the permitted upload landed as {len(landed)!r} bytes with sha256 "
        f"{hashlib.sha256(landed).hexdigest()!r}, sent {len(_OWN)!r} with sha256 "
        f"{hashlib.sha256(_OWN).hexdigest()!r}")

    keys_before = _all_keys(s3, bucket)

    # ---- BREAK EXACTLY ONE THING: ask the confined session for the twin's object. Same server,
    # same key, same role, same moment -- only the requested path is outside the policy.
    rel_rc, _, rel_err = _sftp(ctx, workdir, host, confined, priv,
                               [f'get ../{twin}/secret.txt escaped-relative.bin', 'quit'])
    _assert_refused(rel_rc, rel_err, workdir, 'escaped-relative.bin',
                    what=f'relative ../{twin}/secret.txt out of the scope-down policy')

    abs_rc, _, abs_err = _sftp(
        ctx, workdir, host, confined, priv,
        [f'get /{bucket}/home/{twin}/secret.txt escaped-absolute.bin', 'quit'])
    _assert_refused(abs_rc, abs_err, workdir, 'escaped-absolute.bin',
                    what=f'absolute /{bucket}/home/{twin}/secret.txt out of the scope-down policy')

    # ---- EFFECT ABSENT, on an independent read at the destination: the bucket is unchanged and
    # the twin's object was not touched by either refused attempt.
    keys_after = _all_keys(s3, bucket)
    assert keys_after == keys_before, (
        f"the refused sessions changed the bucket: {sorted(keys_after)!r} vs "
        f"{sorted(keys_before)!r}")
    intruder_after = s3.head_object(Bucket=bucket, Key=f'home/{twin}/secret.txt')
    assert ((intruder_after['ETag'], intruder_after['ContentLength'])
            == (intruder_before['ETag'], intruder_before['ContentLength'])), (
        f"the refused attempts altered the twin's object: "
        f"{(intruder_after['ETag'], intruder_after['ContentLength'])!r} vs "
        f"{(intruder_before['ETag'], intruder_before['ContentLength'])!r}")

    # ---- ATTRIBUTION: the SAME role on the SAME server reads the SAME object when the session
    # policy is not in the way. So the boundary is the Policy and not IAM, the endpoint, or S3.
    twin_rc, _, twin_err = _sftp(ctx, workdir, host, twin, priv,
                                 [f'get {twin}/secret.txt twin.bin', 'quit'])
    assert twin_rc == 0, (
        f"the permissively-scoped twin could not read its own object either, so the refusals "
        f"above cannot be attributed to the scope-down policy: rc {twin_rc!r}, "
        f"stderr {twin_err[-600:]!r}")
    twin_bytes = open(os.path.join(workdir, 'twin.bin'), 'rb').read()
    assert twin_bytes == _INTRUDER, (
        f"the twin read {len(twin_bytes)!r} bytes with sha256 "
        f"{hashlib.sha256(twin_bytes).hexdigest()!r}, expected {len(_INTRUDER)!r} with sha256 "
        f"{hashlib.sha256(_INTRUDER).hexdigest()!r}")

    # ---- RESTORE: widen ONLY the confined user's own policy document -- same user, same role,
    # same key, same command -- and demand the identical get now succeeds. A target that refuses
    # every out-of-home path unconditionally fails here; one that ignores the Policy entirely
    # failed above.
    transfer.update_user(ServerId=server_id, UserName=confined,
                        Policy=_permissive_policy(bucket))
    stored = transfer.describe_user(ServerId=server_id, UserName=confined)['User']
    assert json.loads(stored['Policy']) == json.loads(_permissive_policy(bucket)), (
        f"UpdateUser did not store the widened policy: {stored.get('Policy')!r}")

    def _restored_get():
        rc, _out, err = _sftp(ctx, workdir, host, confined, priv,
                              [f'get ../{twin}/secret.txt restored.bin', 'quit'])
        return rc, err

    # _poll RAISES on exhaustion, so reaching the next line already proves rc == 0; re-asserting
    # that here would be an assertion that cannot fail. The bytes are the assertion.
    _poll(_restored_get, lambda pair: pair[0] == 0,
          timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=10.0,
          what=('the widened session policy to admit the identical get that the '
                'confining policy refused'))

    restored = open(os.path.join(workdir, 'restored.bin'), 'rb').read()
    assert restored == _INTRUDER, (
        f"after widening the policy the identical get returned {len(restored)!r} bytes with "
        f"sha256 {hashlib.sha256(restored).hexdigest()!r}, expected {len(_INTRUDER)!r} with "
        f"sha256 {hashlib.sha256(_INTRUDER).hexdigest()!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
