"""sftpjail-update-user-remaps-the-logical-jail-for-the-next-session."""
from __future__ import annotations

import errno
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
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "sftpjail-update-user-remaps-the-logical-jail-for-the-next-session"
GROUP = 'sftp-rejection'
SERVICES = ['transfer']

# Three distinct 8 KiB payloads over the full octet range, so a truncating or re-encoding server
# cannot make any two of them compare equal.
_KEEP_OLD = bytes(bytearray(range(256)) * 32) + b'\r\n\x00sim2real-keep-old\x00\r\n'
_KEEP_NEW = bytes(bytearray(reversed(range(256))) * 32) + b'\r\n\x00sim2real-keep-new\x00\r\n'
_ONLY_OLD = bytes(bytearray(range(128, 256)) * 64) + b'\r\n\x00sim2real-only-old\x00\r\n'

_ONLINE_TIMEOUT_S = 900.0
_ENDPOINT_TIMEOUT_S = 420.0
_GONE_TIMEOUT_S = 300.0
_REMAP_TIMEOUT_S = 300.0
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

    -m PEM is load-bearing: paramiko's RSAKey reader wants PKCS#1 PEM, and OpenSSH 9.x defaults
    to its own container format instead.
    """
    priv = os.path.join(workdir, f'{stem}-{next(_SEQ)}')
    proc = subprocess.run(
        ['/usr/bin/ssh-keygen', '-q', '-t', 'rsa', '-b', '3072', '-m', 'PEM',
         '-N', '', '-C', 'sim2real', '-f', priv],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"ssh-keygen failed: {proc.stdout!r} {proc.stderr!r}"
    os.chmod(priv, 0o600)
    return priv, open(priv + '.pub').read().strip()


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


def _open_sftp(host: str, user: str, priv: str, *, timeout_s=90.0):
    """One authenticated SFTP session through paramiko -- a third-party SSH implementation
    speaking the real protocol, not an AWS API call. Returns (transport, sftp); the caller closes.

    paramiko rather than the OpenSSH client because the claims below are about SFTP protocol
    statuses (SSH_FX_NO_SUCH_FILE) and about the exact set of names in a synthesised directory,
    and paramiko surfaces both as structured values instead of as English on a subprocess's
    stderr.
    """
    import paramiko

    key = paramiko.RSAKey.from_private_key_file(priv)
    transport = paramiko.Transport((host, 22))  # customer-built AWS host
    transport.banner_timeout = timeout_s
    transport.auth_timeout = timeout_s
    try:
        transport.connect(username=user, pkey=key)
        sftp = paramiko.SFTPClient.from_transport(transport)
        assert sftp is not None, (
            f"{DATAPLANE_MARKER}: authenticated as {user!r} on {host!r} but the sftp subsystem "
            f"could not be opened")
    except BaseException:
        transport.close()
        raise
    return transport, sftp


def _open_sftp_when_ready(host: str, user: str, priv: str, *, timeout_s=240.0, interval_s=10.0):
    """_open_sftp, retried over the window between CreateUser returning and the user being usable.

    The retry IS the wait: it drives the real operation and returns the moment it works, so there
    is no fixed sleep standing in for a condition. Exhaustion is a data-plane FAIL quoting the last
    attempt -- an endpoint that never authenticates the key it was given is the defect.
    """
    import paramiko

    deadline = time.monotonic() + timeout_s
    last = 'never attempted'
    while True:
        try:
            return _open_sftp(host, user, priv)
        except (paramiko.SSHException, OSError, EOFError) as exc:
            last = f'{type(exc).__name__}: {exc}'
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no authenticated SFTP session as {user!r} on {host!r} "
                f"within {timeout_s}s; last attempt: {last}")
        time.sleep(interval_s)


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name('sim2real-sftpjail-').lower().replace('_', '-')
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


def _home_policy(bucket: str):
    return [
        {'Effect': 'Allow', 'Action': ['s3:ListBucket', 's3:GetBucketLocation'],
         'Resource': f'arn:aws:s3:::{bucket}'},
        {'Effect': 'Allow',
         'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:GetObjectVersion',
                    's3:GetObjectACL', 's3:PutObjectACL'],
         'Resource': f'arn:aws:s3:::{bucket}/*'},
    ]


def _create_transfer_role(ctx, iam, statements) -> str:
    role = ctx.unique_name('sim2real-sftpjail-role-')
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


def _describe_state(transfer, server_id: str) -> str:
    try:
        return transfer.describe_server(ServerId=server_id)['Server']['State']
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
            return 'GONE'
        raise


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


def _read_remote(sftp, name: str) -> bytes:
    with sftp.open(name, 'rb') as fh:
        return fh.read()


def _read_status(sftp, name: str):
    """The bytes the session serves for `name`, or paramiko's errno if the server refused.

    Never a falsy sentinel on either outcome: bytes and an errno cannot be confused, so an
    emulator that keeps serving a path the remap removed is reported as the bytes it served
    rather than as an errno mismatch that reads like a naming difference.
    """
    try:
        return _read_remote(sftp, name)
    except IOError as exc:
        assert exc.errno is not None, f"paramiko raised {exc!r} with no errno to assert on"
        return exc.errno


def _observe(host: str, user: str, priv: str, names) -> dict:
    """One FRESH session's whole view of its namespace: the listing plus the status of each name.

    A fresh session per observation on purpose -- the claim is about what the NEXT session sees
    after UpdateUser, so reusing an already-authenticated session would grade a cached mapping.

    A session that cannot be established at all is returned as an `error` entry rather than
    raised, so the caller's poll can retry it and, on exhaustion, quote it. The window between
    CreateUser returning and the user being usable is real and exposes no condition to poll other
    than the connection itself.
    """
    import paramiko

    try:
        transport, sftp = _open_sftp(host, user, priv)
    except (paramiko.SSHException, OSError, EOFError) as exc:
        return {'error': f'{type(exc).__name__}: {exc}'}
    try:
        out = {'root': sorted(sftp.listdir('/'))}
        for name in names:
            out[name] = _read_status(sftp, f'/{name}')
        return out
    finally:
        sftp.close()
        transport.close()


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """After UpdateUser repoints a LOGICAL mapping, the next SFTP session serves the new prefix and
    refuses an old-prefix-only name with SSH_FX_NO_SUCH_FILE, while that object is unchanged in S3
    and a PATH user with the same role still reads it: the mapping, not IAM, is the boundary.
    """
    require_tools("ssh-keygen")
    import paramiko  # noqa: F401

    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)

    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key='old/keep.bin', Body=_KEEP_OLD)
    s3.put_object(Bucket=bucket, Key='old/only-in-old.bin', Body=_ONLY_OLD)
    s3.put_object(Bucket=bucket, Key='new/keep.bin', Body=_KEEP_NEW)
    only_old_before = s3.head_object(Bucket=bucket, Key='old/only-in-old.bin')

    # The WHOLE bucket, on purpose: scoped to one prefix, IAM and not the mapping could be what
    # refuses, and the check would be asserting the wrong subject.
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer)
    _poll(lambda: transfer.describe_server(ServerId=server_id)['Server']['State'],
          lambda s: s == 'ONLINE', timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
          what=f'server {server_id} to reach ONLINE')

    jailed = ctx.unique_name('sim2real-remap-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=jailed, Role=role_arn,
        HomeDirectoryType='LOGICAL',
        HomeDirectoryMappings=[{'Entry': '/', 'Target': f'/{bucket}/old'}],
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=jailed))

    witness = ctx.unique_name('sim2real-witness-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=witness, Role=role_arn,
        HomeDirectory=f'/{bucket}', HomeDirectoryType='PATH',
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=witness))

    host = f'{server_id}.server.transfer.{ctx.region}.amazonaws.com'
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    names = ('keep.bin', 'only-in-old.bin')

    # POSITIVE CONTROL FIRST, which is also the propagation barrier: until the ORIGINAL mapping
    # really serves both names, a later refusal is indistinguishable from a user that was never
    # ready. Polled because the claim is that the session works, never how fast it starts working.
    before = _poll(lambda: _observe(host, jailed, priv, names),
                   lambda o: o.get('keep.bin') == _KEEP_OLD,
                   timeout_s=_REMAP_TIMEOUT_S, interval_s=10.0,
                   what='the original mapping to serve the old prefix')
    assert before['root'] == ['keep.bin', 'only-in-old.bin'], (
        f"the jailed session's root listing is {before['root']!r}; the mapping targets "
        f"{f'/{bucket}/old'!r} which holds keep.bin and only-in-old.bin")
    assert before['only-in-old.bin'] == _ONLY_OLD, (
        f"the old-prefix-only object read back {before['only-in-old.bin']!r:.80} under the "
        f"original mapping, expected {len(_ONLY_OLD)!r} bytes with sha256 "
        f"{hashlib.sha256(_ONLY_OLD).hexdigest()!r}")

    # BREAK EXACTLY ONE THING: repoint the mapping's Target. Nothing else changes -- same user,
    # same key, same server, same role, same bucket.
    transfer.update_user(ServerId=server_id, UserName=jailed,
                         HomeDirectoryMappings=[{'Entry': '/', 'Target': f'/{bucket}/new'}])

    described = transfer.describe_user(ServerId=server_id,
                                       UserName=jailed)['User']['HomeDirectoryMappings']
    assert described == [{'Entry': '/', 'Target': f'/{bucket}/new'}], (
        f"DescribeUser reports {described!r} after UpdateUser, not the new target "
        f"{f'/{bucket}/new'!r}")

    # Convergence: the next session's view ARRIVES at the new prefix. Polled for the value, with
    # no assertion about how long it takes.
    after = _poll(lambda: _observe(host, jailed, priv, names),
                  lambda o: o.get('keep.bin') == _KEEP_NEW,
                  timeout_s=_REMAP_TIMEOUT_S, interval_s=10.0,
                  what='a new session to serve the remapped prefix for keep.bin')

    # EFFECT ABSENT: the name that exists only under the old prefix is gone from the namespace.
    assert after['only-in-old.bin'] == errno.ENOENT, (
        f"after the remap the old-prefix-only name read back "
        f"{after['only-in-old.bin']!r:.80} instead of being refused with SSH_FX_NO_SUCH_FILE "
        f"({errno.ENOENT!r})")
    assert after['root'] == ['keep.bin'], (
        f"the remapped session's root listing is {after['root']!r}; the new target "
        f"{f'/{bucket}/new'!r} holds only keep.bin")

    # ATTRIBUTION 1: the object is still in the backing store, unchanged, so the refusal is not a
    # deletion.
    only_old_after = s3.head_object(Bucket=bucket, Key='old/only-in-old.bin')
    assert (only_old_after['ETag'], only_old_after['ContentLength']) == (
            only_old_before['ETag'], only_old_before['ContentLength']), (
        f"the remap altered the old object: {only_old_after['ETag']!r}/"
        f"{only_old_after['ContentLength']!r} vs {only_old_before['ETag']!r}/"
        f"{only_old_before['ContentLength']!r}")

    # ATTRIBUTION 2: same server, same role, no mapping in the way -- the very key the remapped
    # session was refused comes back with its exact bytes. So the boundary is the mapping.
    transport, sftp = _open_sftp_when_ready(host, witness, priv)
    try:
        witnessed = _read_remote(sftp, f'/{bucket}/old/only-in-old.bin')
    finally:
        sftp.close()
        transport.close()
    assert witnessed == _ONLY_OLD, (
        f"the unmapped user could not read the old key either, so the refusal above cannot be "
        f"attributed to the mapping: got {len(witnessed)!r} bytes with sha256 "
        f"{hashlib.sha256(witnessed).hexdigest()!r}, expected {len(_ONLY_OLD)!r} with "
        f"{hashlib.sha256(_ONLY_OLD).hexdigest()!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
