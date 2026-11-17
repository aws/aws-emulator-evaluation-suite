"""transfer-preauthentication-login-banner-is-delivered-before-authentication."""
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

CHECK = "transfer-preauthentication-login-banner-is-delivered-before-authentication"
GROUP = 'sftp-data-plane'
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

_PAYLOAD = b'sim2real banner payload \x00\xff\r\n' * 128

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


def _banner_seen(ctx, workdir: str, host: str, user: str, priv: str, nonce: str) -> tuple:
    """One session, returning (rc, stderr) -- the banner is a stderr artefact, so stderr is the
    observable. Kept as a helper so the banner-bearing session shape is IDENTICAL across the
    failed-auth, succeeded-auth, changed and restored legs; any difference between them would then
    be about the banner and not about how it was asked for."""
    del nonce  # the caller asserts on the returned stderr; this helper must not decide the verdict
    return _sftp(ctx, workdir, host, user, priv, ['pwd', 'quit'])


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """PreAuthenticationLoginBanner is delivered over SSH before authentication: a refused session
    with an unregistered key still receives it, an authorised session receives it and uploads, and
    UpdateServer changes what the next connection receives until it is restored.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    account = ctx.client('sts').get_caller_identity()['Account']
    assert account.isdigit() and len(account) == 12, (
        f"GetCallerIdentity returned a malformed account id {account!r}")

    # Nonces, not fixed strings: a shared sandbox may hold another run's server, and a fixed banner
    # could be matched against the wrong one.
    first_nonce = ctx.unique_name('sim2real-preauth-first-')
    second_nonce = ctx.unique_name('sim2real-preauth-second-')
    assert first_nonce != second_nonce, "the two banner nonces collided"

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir, 'registered')
    stranger_priv, stranger_pub = _keygen(workdir, 'never-registered')
    assert pub != stranger_pub, "ssh-keygen produced the same key twice"
    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_PAYLOAD)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer, PreAuthenticationLoginBanner=first_nonce)
    described = _online(ctx, transfer, server_id)
    assert described.get('PreAuthenticationLoginBanner') == first_nonce, (
        f"DescribeServer reports the banner as "
        f"{described.get('PreAuthenticationLoginBanner')!r}, expected {first_nonce!r}; the rest of "
        f"this check would be asserting the wrong configuration")

    user = ctx.unique_name('sim2real-banner-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    host = _host(ctx, server_id)
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    # ---- POSITIVE CONTROL FIRST: an authorised session works at all, which is also the
    # propagation barrier -- until a real login succeeds, a missing banner is indistinguishable
    # from an endpoint or a user that is not ready.
    ok_rc, _ok_out, ok_err = _sftp(ctx, workdir, host, user, priv,
                                   [f'put {local_up} banner-control.bin', 'quit'])
    assert ok_rc == 0, (
        f"the authorised session failed, so nothing below can be attributed to the banner: "
        f"rc {ok_rc!r}, stderr {ok_err[-600:]!r}")
    landed = s3.get_object(Bucket=bucket, Key='home/banner-control.bin')['Body'].read()
    assert landed == _PAYLOAD, (
        f"the authorised upload landed as {len(landed)!r} bytes with sha256 "
        f"{hashlib.sha256(landed).hexdigest()!r}, sent {len(_PAYLOAD)!r} with sha256 "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")
    assert first_nonce in ok_err, (
        f"the authorised session never received the pre-authentication banner {first_nonce!r}; "
        f"stderr {ok_err[-800:]!r}")

    # ---- THE ORDERING ASSERTION: a session that never authenticates must STILL have received the
    # banner, because the banner precedes authentication.
    bad_rc, _bad_out, bad_err = _banner_seen(ctx, workdir, host, user, stranger_priv, first_nonce)
    assert 'Permission denied (publickey)' in bad_err, (
        f"the never-registered key was not refused with a publickey denial, so this session does "
        f"not demonstrate pre-authentication delivery: rc {bad_rc!r}, stderr {bad_err[-800:]!r}")
    assert first_nonce in bad_err, (
        f"a session that FAILED authentication did not receive the pre-authentication banner "
        f"{first_nonce!r}, so the banner is not being sent before authentication; "
        f"stderr {bad_err[-800:]!r}")

    # ---- BREAK EXACTLY ONE THING: the banner text. Same server, same ONLINE state, same user,
    # same keys, same command.
    transfer.update_server(ServerId=server_id, PreAuthenticationLoginBanner=second_nonce)
    echoed = transfer.describe_server(ServerId=server_id)['Server']
    assert echoed.get('PreAuthenticationLoginBanner') == second_nonce, (
        f"UpdateServer did not store the new banner: "
        f"{echoed.get('PreAuthenticationLoginBanner')!r} vs {second_nonce!r}")

    changed = _poll(
        lambda: _banner_seen(ctx, workdir, host, user, stranger_priv, second_nonce),
        lambda triple: second_nonce in triple[2],
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=10.0,
        what='the updated pre-authentication banner to reach a new connection')
    # The OLD text must be GONE. Without this the check would pass against a target that appends
    # every banner it has ever been given.
    assert first_nonce not in changed[2], (
        f"after the banner was changed to {second_nonce!r} the connection still received the old "
        f"text {first_nonce!r}; stderr {changed[2][-800:]!r}")

    # ---- RESTORE: put the original text back and demand the identical connection receives it
    # again, and not the replacement.
    transfer.update_server(ServerId=server_id, PreAuthenticationLoginBanner=first_nonce)
    restored = _poll(
        lambda: _banner_seen(ctx, workdir, host, user, stranger_priv, first_nonce),
        lambda triple: first_nonce in triple[2],
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=10.0,
        what='the restored pre-authentication banner to reach a new connection')
    assert second_nonce not in restored[2], (
        f"after restoring {first_nonce!r} the connection still received {second_nonce!r}; "
        f"stderr {restored[2][-800:]!r}")

    # ---- TERMINAL READ at the destination, through a different operation than the mutation: the
    # authorised session's bytes are in S3, and the bucket holds exactly the one object the banner
    # legs were never supposed to add to.
    final = _all_keys(s3, bucket)
    assert final == {'home/banner-control.bin'}, (
        f"the banner legs changed the bucket: expected only the control upload, got "
        f"{sorted(final)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
