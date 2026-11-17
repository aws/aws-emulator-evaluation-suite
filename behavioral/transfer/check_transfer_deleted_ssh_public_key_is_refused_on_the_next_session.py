"""transfer-deleted-ssh-public-key-is-refused-on-the-next-session."""
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

CHECK = "transfer-deleted-ssh-public-key-is-refused-on-the-next-session"
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

_PAYLOAD = b'sim2real revocation payload \x00\xff\r\n' * 128

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


def _key_ids(transfer, server_id: str, user: str) -> dict:
    """material -> SshPublicKeyId for every key registered on the user.

    Keyed on the base64 key MATERIAL rather than the whole body: the service is free to normalise
    the trailing comment, and that is not what any assertion here is about.
    """
    described = transfer.describe_user(ServerId=server_id, UserName=user)['User']
    return {k['SshPublicKeyBody'].split()[1]: k['SshPublicKeyId']
            for k in described['SshPublicKeys']}


def _error(fn) -> tuple:
    """The (code, message) of a call that MUST fail. Raises on unexpected success -- never a falsy
    sentinel, which would let an over-permissive target disguise acceptance as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError("the call succeeded but was required to fail")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """DeleteSshPublicKey refuses that key on the next SFTP session with a publickey denial that
    writes nothing, while the user's surviving key still authenticates and uploads, and
    re-importing the revoked body restores it.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    account = ctx.client('sts').get_caller_identity()['Account']
    assert account.isdigit() and len(account) == 12, (
        f"GetCallerIdentity returned a malformed account id {account!r}")

    workdir = _workdir(ctx)
    revoked_priv, revoked_pub = _keygen(workdir, 'to-be-revoked')
    survivor_priv, survivor_pub = _keygen(workdir, 'survivor')
    assert revoked_pub != survivor_pub, "ssh-keygen produced the same key twice"
    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_PAYLOAD)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer)
    _online(ctx, transfer, server_id)

    user = ctx.unique_name('sim2real-revoke-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        SshPublicKeyBody=revoked_pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    transfer.import_ssh_public_key(ServerId=server_id, UserName=user,
                                   SshPublicKeyBody=survivor_pub)

    ids = _key_ids(transfer, server_id, user)
    assert set(ids) == {revoked_pub.split()[1], survivor_pub.split()[1]}, (
        f"the user must hold exactly the two imported keys, DescribeUser reports "
        f"{sorted(ids)!r}")
    revoked_id = ids[revoked_pub.split()[1]]

    host = _host(ctx, server_id)
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    # ---- POSITIVE CONTROL ON BOTH KEYS FIRST. Without this, "the revoked key is refused" is
    # indistinguishable from "this key never worked" and from "this server refuses everything".
    for label, priv in (('revoked-key-before', revoked_priv), ('survivor-key-before',
                                                               survivor_priv)):
        rc, _out, err = _sftp(ctx, workdir, host, user, priv,
                              [f'put {local_up} {label}.bin', 'quit'])
        assert rc == 0, (
            f"{label}: the key could not log in BEFORE any revocation, so nothing below is "
            f"attributable: rc {rc!r}, stderr {err[-600:]!r}")
        body = s3.get_object(Bucket=bucket, Key=f'home/{label}.bin')['Body'].read()
        assert body == _PAYLOAD, (
            f"{label}: the upload landed as {len(body)!r} bytes with sha256 "
            f"{hashlib.sha256(body).hexdigest()!r}, sent {len(_PAYLOAD)!r} with sha256 "
            f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    # ---- BREAK EXACTLY ONE THING: revoke one of the two keys.
    transfer.delete_ssh_public_key(ServerId=server_id, UserName=user, SshPublicKeyId=revoked_id)

    keys_before = _all_keys(s3, bucket)

    # The revoked key must be refused. Bounded, because revocation may not be instantaneous; the
    # poll RAISES if the key is still accepted when the deadline passes, so a target that never
    # revokes fails rather than waits forever.
    def _attempt_revoked():
        rc, _out, err = _sftp(ctx, workdir, host, user, revoked_priv,
                              [f'put {local_up} revoked-after.bin', 'quit'])
        return rc, err

    rc_after, err_after = _poll(
        _attempt_revoked, lambda pair: pair[0] != 0,
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=10.0,
        what='the revoked SSH public key to stop authenticating after DeleteSshPublicKey')
    assert 'Permission denied (publickey)' in err_after, (
        f"the revoked key was not refused with a publickey denial: rc {rc_after!r}, "
        f"stderr {err_after[-800:]!r}")

    # ---- EFFECT ABSENT, independent read at the destination: the refused sessions wrote nothing.
    keys_after = _all_keys(s3, bucket)
    assert keys_after == keys_before, (
        f"a session using the revoked key still changed the bucket: {sorted(keys_after)!r} vs "
        f"{sorted(keys_before)!r}")

    # ---- SURVIVING-KEY POSITIVE CONTROL, in the same instant: the revocation was about ONE key.
    surv_rc, _, surv_err = _sftp(ctx, workdir, host, user, survivor_priv,
                                 [f'put {local_up} survivor-after.bin', 'quit'])
    assert surv_rc == 0, (
        f"deleting one key also stopped the OTHER key from authenticating, so the revocation is "
        f"not key-scoped: rc {surv_rc!r}, stderr {surv_err[-600:]!r}")
    surv_body = s3.get_object(Bucket=bucket, Key='home/survivor-after.bin')['Body'].read()
    assert surv_body == _PAYLOAD, (
        f"the surviving key's upload landed as {len(surv_body)!r} bytes, sent "
        f"{len(_PAYLOAD)!r}; sha256 {hashlib.sha256(surv_body).hexdigest()!r} vs "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    # ---- The revoked id is gone and unusable: an independent read no longer lists it, and a
    # MUTATION on the dead id fails with the specific not-found code.
    remaining = _key_ids(transfer, server_id, user)
    assert set(remaining) == {survivor_pub.split()[1]}, (
        f"after revoking one key DescribeUser must report exactly the survivor, got "
        f"{sorted(remaining)!r}")
    dead_code, dead_message = _error(lambda: transfer.delete_ssh_public_key(
        ServerId=server_id, UserName=user, SshPublicKeyId=revoked_id))
    assert dead_code == 'ResourceNotFoundException', (
        f"DeleteSshPublicKey on the already-revoked id {revoked_id!r} must fail with "
        f"ResourceNotFoundException, got {dead_code!r}")
    assert dead_message == 'Unknown public key ID', (
        f"expected message 'Unknown public key ID', got {dead_message!r}")

    # ---- RESTORE: re-import the identical public-key body and demand the identical command that
    # was just refused now succeeds. A target that never really revoked failed above; one that
    # revoked permanently, or that rejects the re-import as a duplicate, fails here.
    reimported = transfer.import_ssh_public_key(
        ServerId=server_id, UserName=user, SshPublicKeyBody=revoked_pub)
    assert reimported['SshPublicKeyId'] != revoked_id, (
        f"re-importing the revoked body reused the revoked SshPublicKeyId {revoked_id!r}, so the "
        f"deletion did not retire the identifier: {reimported!r}")

    def _attempt_restored():
        rc, _out, err = _sftp(ctx, workdir, host, user, revoked_priv,
                              [f'put {local_up} restored.bin', 'quit'])
        return rc, err

    # _poll RAISES on exhaustion, so reaching the next line already proves rc == 0; re-asserting
    # it would be an assertion that cannot fail. The bytes in S3 are the assertion.
    _poll(_attempt_restored, lambda pair: pair[0] == 0,
          timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=10.0,
          what='the re-imported SSH public key to authenticate again')

    # Terminal read at the destination, through a different operation than the mutation: the bytes
    # the restored session wrote, fetched from S3 rather than from the SFTP client's own exit code.
    restored_body = s3.get_object(Bucket=bucket, Key='home/restored.bin')['Body'].read()
    assert restored_body == _PAYLOAD, (
        f"the restored key's upload landed as {len(restored_body)!r} bytes with sha256 "
        f"{hashlib.sha256(restored_body).hexdigest()!r}, sent {len(_PAYLOAD)!r} with sha256 "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
