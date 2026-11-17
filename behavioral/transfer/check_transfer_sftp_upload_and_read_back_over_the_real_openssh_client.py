"""transfer-sftp-upload-and-read-back-over-the-real-openssh-client."""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "transfer-sftp-upload-and-read-back-over-the-real-openssh-client"
GROUP = 'sftp-data-plane'
SERVICES = ['transfer']

# The bytes are the point: 64 KiB spanning the full octet range with embedded NULs and
# CRLFs, so a server that mangled encodings or truncated at a control byte cannot
# round-trip it.
_PAYLOAD = bytes(bytearray(range(256)) * 256) + b'\r\n\x00sim2real\x00\r\n'

_ONLINE_TIMEOUT_S = 900.0
_ENDPOINT_TIMEOUT_S = 420.0
_GONE_TIMEOUT_S = 300.0
_INTERVAL_S = 15.0

# Carried in a failure detail when the server host accepts no SSH connection, so a missing SFTP
# data plane reads as a failed check rather than as a client connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_SEQ = itertools.count()


# ===== helpers =====
def _poll(fn, pred, *, timeout_s, interval_s, what):
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
    the propagation codes IS the wait; there is no fixed sleep standing in for it.
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


def _keygen(workdir: str, stem: str = 'sim2real-key') -> tuple[str, str]:
    """Generate an RSA keypair with the real ssh-keygen. Returns (private path, public body).

    -m PEM is load-bearing: the SFTP connector's Secrets Manager format wants PKCS#1 PEM, and
    OpenSSH 9.x defaults to its own container format instead.
    """
    priv = os.path.join(workdir, stem)
    proc = subprocess.run(
        ['/usr/bin/ssh-keygen', '-q', '-t', 'rsa', '-b', '3072', '-m', 'PEM',
         '-N', '', '-C', 'sim2real', '-f', priv],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"ssh-keygen failed: {proc.stdout!r} {proc.stderr!r}"
    os.chmod(priv, 0o600)
    return priv, open(priv + '.pub').read().strip()


def _sftp(ctx, workdir: str, host: str, user: str, priv: str, lines, *,
          timeout_s=300.0, extra=()):
    """One non-interactive session through /usr/bin/sftp — the real OpenSSH client.

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
        # does not -- and it is verified gone rather than fired and forgotten.
        transfer.delete_server(ServerId=server_id)
        _poll(lambda: _describe_state(transfer, server_id), lambda s: s == 'GONE',
              timeout_s=_GONE_TIMEOUT_S, interval_s=10.0,
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


def _all_keys(s3, bucket: str, prefix: str = '') -> set[str]:
    """Every key in the bucket, fully paginated. The sandbox accounts are a shared pool and a
    membership assertion off page one is a latent flake, not a fidelity signal."""
    keys = set()
    for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
        keys.update(o['Key'] for o in page.get('Contents', []))
    return keys


def _head_code(s3, bucket: str, key: str) -> str:
    """'200' if the object is there, else the HTTP status of the HeadObject refusal."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return str(exc.response['ResponseMetadata']['HTTPStatusCode'])
    return '200'


def _sftp_names(stdout: str) -> set[str]:
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


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Transfer server speaks SFTP to the OpenSSH client: it authenticates with the imported key,
    uploads 64 KiB and reads it back byte-identically, and the same bytes are in S3 under the
    user's home prefix.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)
    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_PAYLOAD)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer)
    server = _poll(lambda: transfer.describe_server(ServerId=server_id)['Server'],
                   lambda srv: srv['State'] == 'ONLINE',
                   timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
                   what=f'server {server_id} to reach ONLINE')

    user = ctx.unique_name('sim2real-dp-user-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    host = f'{server_id}.server.transfer.{ctx.region}.amazonaws.com'
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    remote = 'roundtrip.bin'
    up_rc, _, up_err = _sftp(ctx, workdir, host, user, priv,
                             [f'put {local_up} {remote}', 'quit'])
    assert up_rc == 0, f"sftp put exited {up_rc!r}: {up_err[-600:]!r}"

    s3_body = s3.get_object(Bucket=bucket, Key=f'home/{remote}')['Body'].read()
    assert s3_body == _PAYLOAD, (
        f"S3 holds {len(s3_body)!r} bytes with sha256 {hashlib.sha256(s3_body).hexdigest()!r}; "
        f"uploaded {len(_PAYLOAD)!r} bytes with sha256 "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    down_rc, _, down_err = _sftp(ctx, workdir, host, user, priv,
                                 [f'get {remote} downloaded.bin', 'quit'])
    assert down_rc == 0, f"sftp get exited {down_rc!r}: {down_err[-600:]!r}"
    downloaded = open(os.path.join(workdir, 'downloaded.bin'), 'rb').read()
    assert downloaded == _PAYLOAD, (
        f"the round-tripped file is {len(downloaded)!r} bytes, uploaded {len(_PAYLOAD)!r}; "
        f"sha256 {hashlib.sha256(downloaded).hexdigest()!r} vs "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    ls_rc, listing, ls_err = _sftp(ctx, workdir, host, user, priv, ['ls -l', 'quit'])
    assert ls_rc == 0, f"sftp ls exited {ls_rc!r}: {ls_err[-600:]!r}"
    assert str(len(_PAYLOAD)) in listing, (
        f"the remote listing does not show the uploaded size {len(_PAYLOAD)!r}: {listing!r}")

    final_state = transfer.describe_server(ServerId=server_id)['Server']['State']
    assert final_state == 'ONLINE', (
        f"server {server_id} reads {final_state!r} via a fresh DescribeServer "
        f"after the round trip, not ONLINE")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
