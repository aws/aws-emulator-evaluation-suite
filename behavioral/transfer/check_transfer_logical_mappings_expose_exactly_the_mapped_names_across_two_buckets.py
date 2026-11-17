"""transfer-logical-mappings-expose-exactly-the-mapped-names-across-two-buckets."""
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
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "transfer-logical-mappings-expose-exactly-the-mapped-names-across-two-buckets"
GROUP = 'sftp-data-plane'
SERVICES = ['transfer']

_PAYLOAD_A = b'sim2real inbox bytes \x00\xff\n' * 32
_PAYLOAD_B = b'sim2real archive bytes \x00\xfe\n' * 32

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
    """A private scratch dir for this run. Never a fixed /tmp path: the host may run other checks
    at once, and a predictable name lets one run overwrite another's private key."""
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
    """Every key in the bucket, fully paginated: a membership assertion on page one alone is a
    latent flake."""
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
    """LOGICAL HomeDirectoryMappings rewrite the SFTP namespace: `ls /` shows exactly the two mapped
    entry names, and a put into each lands in that entry's own bucket at the mapped prefix with the
    exact bytes.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)
    local_a = os.path.join(workdir, 'a.bin')
    local_b = os.path.join(workdir, 'b.bin')
    with open(local_a, 'wb') as fh:
        fh.write(_PAYLOAD_A)
    with open(local_b, 'wb') as fh:
        fh.write(_PAYLOAD_B)

    bucket_in = _create_bucket(ctx, s3)
    bucket_arch = _create_bucket(ctx, s3)
    assert bucket_in != bucket_arch, "the two buckets collided"
    role_arn = _create_transfer_role(
        ctx, iam, _home_policy(bucket_in) + _home_policy(bucket_arch))

    server_id = _create_server(ctx, transfer)
    _poll(lambda: transfer.describe_server(ServerId=server_id)['Server']['State'],
          lambda s: s == 'ONLINE', timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
          what=f'server {server_id} to reach ONLINE')

    user = ctx.unique_name('sim2real-map-u-').replace('_', '-').lower()
    mappings = [{'Entry': '/inbox', 'Target': f'/{bucket_in}/in'},
                {'Entry': '/archive', 'Target': f'/{bucket_arch}/arch'}]
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectoryType='LOGICAL', HomeDirectoryMappings=mappings,
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    host = f'{server_id}.server.transfer.{ctx.region}.amazonaws.com'
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    # The puts come FIRST: with both mapped targets still empty, `ls /` returns nothing at all.
    # AWS does not synthesise an entry for a mapping whose target prefix holds no object, so the
    # root listing is only meaningful once each entry has content.
    put_rc, _, put_err = _sftp(ctx, workdir, host, user, priv,
                               [f'put {local_a} /inbox/a.bin',
                                f'put {local_b} /archive/b.bin', 'quit'])
    assert put_rc == 0, f"the mapped puts exited {put_rc!r}: {put_err[-600:]!r}"

    root_rc, root_out, root_err = _sftp(ctx, workdir, host, user, priv, ['ls /', 'quit'])
    assert root_rc == 0, f"sftp 'ls /' exited {root_rc!r}: {root_err[-600:]!r}"
    root_names = _sftp_names(root_out)
    assert root_names == {'inbox', 'archive'}, (
        f"the synthesised root listing shows {sorted(root_names)!r}, expected exactly the two "
        f"mapped entry names; raw listing {root_out!r}")

    in_rc, in_out, in_err = _sftp(ctx, workdir, host, user, priv, ['ls /inbox', 'quit'])
    assert in_rc == 0, f"sftp 'ls /inbox' exited {in_rc!r}: {in_err[-600:]!r}"
    assert _sftp_names(in_out) == {'inbox/a.bin'}, (
        f"the /inbox entry lists {sorted(_sftp_names(in_out))!r}, expected only the object put "
        f"through it; raw listing {in_out!r}")

    arch_rc, arch_out, arch_err = _sftp(ctx, workdir, host, user, priv, ['ls /archive', 'quit'])
    assert arch_rc == 0, f"sftp 'ls /archive' exited {arch_rc!r}: {arch_err[-600:]!r}"
    assert _sftp_names(arch_out) == {'archive/b.bin'}, (
        f"the /archive entry lists {sorted(_sftp_names(arch_out))!r}, expected only the object put "
        f"through it; raw listing {arch_out!r}")

    in_body = s3.get_object(Bucket=bucket_in, Key='in/a.bin')['Body'].read()
    assert in_body == _PAYLOAD_A, (
        f"/inbox routed {len(in_body)!r} bytes into {bucket_in!r}, sent {len(_PAYLOAD_A)!r}; "
        f"sha256 {hashlib.sha256(in_body).hexdigest()!r} vs "
        f"{hashlib.sha256(_PAYLOAD_A).hexdigest()!r}")
    arch_body = s3.get_object(Bucket=bucket_arch, Key='arch/b.bin')['Body'].read()
    assert arch_body == _PAYLOAD_B, (
        f"/archive routed {len(arch_body)!r} bytes into {bucket_arch!r}, sent "
        f"{len(_PAYLOAD_B)!r}; sha256 {hashlib.sha256(arch_body).hexdigest()!r} vs "
        f"{hashlib.sha256(_PAYLOAD_B).hexdigest()!r}")

    assert _all_keys(s3, bucket_in) == {'in/a.bin'}, (
        f"the inbox bucket holds {sorted(_all_keys(s3, bucket_in))!r}, expected only the mapped "
        f"prefix -- a mapping that leaked would put the object somewhere else")
    assert _all_keys(s3, bucket_arch) == {'arch/b.bin'}, (
        f"the archive bucket holds {sorted(_all_keys(s3, bucket_arch))!r}, expected only "
        f"'arch/b.bin'")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
