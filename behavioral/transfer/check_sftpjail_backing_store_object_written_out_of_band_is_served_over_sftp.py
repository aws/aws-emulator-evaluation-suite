"""sftpjail-backing-store-object-written-out-of-band-is-served-over-sftp."""
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
from fidelity_tests_runner import RequiredToolMissing, require_tools
from botocore.exceptions import ClientError

CHECK = "sftpjail-backing-store-object-written-out-of-band-is-served-over-sftp"
GROUP = 'sftp-data-plane'
SERVICES = ['transfer']

# 64 KiB spanning the full octet range with embedded NULs and CRLFs, so a server that mangled
# encodings or truncated at a control byte cannot round-trip it. Two distinct payloads: one is
# deleted out of band, the other is the positive control that must survive in the same session.
_SERVED = bytes(bytearray(range(256)) * 256) + b'\r\n\x00sim2real-served\x00\r\n'
_CONTROL = bytes(bytearray(reversed(range(256))) * 256) + b'\r\n\x00sim2real-control\x00\r\n'

_ONLINE_TIMEOUT_S = 900.0
_ENDPOINT_TIMEOUT_S = 420.0
_GONE_TIMEOUT_S = 300.0
_VISIBLE_TIMEOUT_S = 180.0
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
    statuses (SSH_FX_NO_SUCH_FILE) and about a directory listing, and paramiko surfaces both as
    structured values instead of as English on a subprocess's stderr.
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


def _all_keys(s3, bucket: str, prefix: str = '') -> set[str]:
    """Every key under `prefix`, fully paginated. The sandbox accounts are a shared pool and a
    membership assertion off page one is a latent flake, not a fidelity signal."""
    keys = set()
    for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
        keys.update(o['Key'] for o in page.get('Contents', []))
    return keys


def _read_remote(sftp, name: str) -> bytes:
    with sftp.open(name, 'rb') as fh:
        return fh.read()


def _read_status(sftp, name: str):
    """The SFTP status of a read, as paramiko's errno -- or the string 'SERVED' when the read
    succeeded.

    Never a falsy sentinel on success: an emulator that serves an object the backing store no
    longer holds is the strongest signal available here, and returning 0 would disguise it as an
    errno mismatch that reads like a naming difference.
    """
    try:
        _read_remote(sftp, name)
    except IOError as exc:
        assert exc.errno is not None, f"paramiko raised {exc!r} with no errno to assert on"
        return exc.errno
    return 'SERVED'


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An object written straight to S3 is listed, stat'ed and read byte-identically over SFTP, and
    deleting it out of band makes the SFTP read fail with SSH_FX_NO_SUCH_FILE while a control object
    still reads in the same session: S3 backs the SFTP namespace in both directions.
    """
    require_tools("ssh-keygen")
    try:
        import paramiko  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(["paramiko"], "module") from exc

    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer)
    _poll(lambda: transfer.describe_server(ServerId=server_id)['Server']['State'],
          lambda s: s == 'ONLINE', timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
          what=f'server {server_id} to reach ONLINE')

    user = ctx.unique_name('sim2real-oob-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    # Seeded with the HARNESS's own credentials straight into the bucket. The server never saw
    # these bytes arrive, so anything it serves for them it must have read from S3.
    s3.put_object(Bucket=bucket, Key='home/served.bin', Body=_SERVED)
    s3.put_object(Bucket=bucket, Key='home/control.bin', Body=_CONTROL)

    host = f'{server_id}.server.transfer.{ctx.region}.amazonaws.com'
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    transport, sftp = _open_sftp_when_ready(host, user, priv)
    try:
        # SSH_FXP_REALPATH, the same call the OpenSSH client makes on connect: with
        # HomeDirectoryType=PATH the session's own view of where it stands is the real bucket path.
        home = sftp.normalize('.')
        assert home == f'/{bucket}/home', (
            f"the session resolves its home to {home!r}; CreateUser was given "
            f"{f'/{bucket}/home'!r} with HomeDirectoryType=PATH")

        # Convergence: poll for the seeded names to ARRIVE in the synthesised namespace, never for
        # how fast they arrive.
        listing = _poll(lambda: set(sftp.listdir(home)),
                        lambda names: {'served.bin', 'control.bin'} <= names,
                        timeout_s=_VISIBLE_TIMEOUT_S, interval_s=5.0,
                        what='the out-of-band objects to appear in the SFTP listing')
        assert listing == {'served.bin', 'control.bin'}, (
            f"the session's home listing is {sorted(listing)!r}; the only keys under the home "
            f"prefix are {sorted(_all_keys(s3, bucket, 'home/'))!r}")

        stat = sftp.stat(f'{home}/served.bin')
        assert stat.st_size == len(_SERVED), (
            f"SFTP stat reports {stat.st_size!r} bytes for served.bin; the object in S3 is "
            f"{len(_SERVED)!r} bytes")

        served = _read_remote(sftp, f'{home}/served.bin')
        assert served == _SERVED, (
            f"the SFTP read returned {len(served)!r} bytes with sha256 "
            f"{hashlib.sha256(served).hexdigest()!r}; S3 holds {len(_SERVED)!r} bytes with "
            f"sha256 {hashlib.sha256(_SERVED).hexdigest()!r}")

        # BREAK EXACTLY ONE THING: remove that one object from the backing store out of band.
        s3.delete_object(Bucket=bucket, Key='home/served.bin')
        assert _all_keys(s3, bucket, 'home/') == {'home/control.bin'}, (
            f"the out-of-band delete did not leave exactly the control object behind: "
            f"{sorted(_all_keys(s3, bucket, 'home/'))!r}")

        # EFFECT ABSENT: the same session, the same name, now a protocol-level refusal. Polled
        # because the claim is that the refusal ARRIVES, never how fast; 'SERVED' is what the last
        # observation reads as if the server keeps serving bytes S3 no longer holds.
        code = _poll(lambda: _read_status(sftp, f'{home}/served.bin'),
                     lambda v: v == errno.ENOENT,
                     timeout_s=_VISIBLE_TIMEOUT_S, interval_s=5.0,
                     what='the deleted object to stop being served over SFTP')
        assert code == errno.ENOENT, (
            f"reading the deleted object failed with errno {code!r}, not "
            f"SSH_FX_NO_SUCH_FILE ({errno.ENOENT!r})")

        after = set(sftp.listdir(home))
        assert after == {'control.bin'}, (
            f"the listing after the out-of-band delete is {sorted(after)!r}, expected only the "
            f"control object")

        # POSITIVE CONTROL, in the same session: the other seeded object is untouched.
        control = _read_remote(sftp, f'{home}/control.bin')
        assert control == _CONTROL, (
            f"the control object read back {len(control)!r} bytes with sha256 "
            f"{hashlib.sha256(control).hexdigest()!r}; S3 holds {len(_CONTROL)!r} bytes with "
            f"sha256 {hashlib.sha256(_CONTROL).hexdigest()!r}")
    finally:
        sftp.close()
        transport.close()

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
