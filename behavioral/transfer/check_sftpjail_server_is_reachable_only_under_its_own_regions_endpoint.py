"""sftpjail-server-is-reachable-only-under-its-own-regions-endpoint."""
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
from fidelity_tests_runner import RequiredToolMissing, require_tools
from botocore.exceptions import ClientError

CHECK = "sftpjail-server-is-reachable-only-under-its-own-regions-endpoint"
GROUP = 'sftp-rejection'
SERVICES = ['transfer']

# 64 KiB spanning the full octet range with embedded NULs and CRLFs, so a server that mangled
# encodings or truncated at a control byte cannot round-trip it.
_PAYLOAD = bytes(bytearray(range(256)) * 256) + b'\r\n\x00sim2real-region\x00\r\n'

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


def _resolves(host: str):
    """The sorted addresses `host` resolves to, or None when the name does not exist.

    Only gaierror is absorbed: anything else is a resolver failure rather than an answer about the
    name, and must not read as "the name is absent".
    """
    try:
        infos = socket.getaddrinfo(host, 22, type=socket.SOCK_STREAM)  # customer-built AWS host
    except socket.gaierror:
        return None
    return sorted({info[4][0] for info in infos})


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


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) of a call expected to fail.

    Raises rather than returning a sentinel when the call SUCCEEDS: an emulator that serves a
    resource from the wrong region is the strongest signal available here, and a falsy return
    would disguise it as a code mismatch that reads like a naming difference.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _server_ids(transfer) -> set[str]:
    """Every ServerId visible to this client, fully paginated. Membership off page one is a latent
    flake in a shared pool, not a fidelity signal."""
    ids = set()
    token = None
    while True:
        page = transfer.list_servers(**({'NextToken': token} if token else {}))
        ids.update(s['ServerId'] for s in page.get('Servers', []))
        token = page.get('NextToken')
        if not token:
            return ids


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A Transfer server serves SFTP under its own region's endpoint only: the same server id under
    a second enabled region's endpoint name does not resolve, and that region's DescribeServer
    returns ResourceNotFoundException.
    """
    require_tools("ssh-keygen")
    try:
        import paramiko  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(["paramiko"], "module") from exc

    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')
    ec2 = ctx.client('ec2')

    # Every decidable precondition BEFORE the first create: a region derivation evaluated after the
    # provisioning wait bills an endpoint-hour for an answer available at the start.
    enabled = {r['RegionName']: r['OptInStatus'] for r in ec2.describe_regions()['Regions']}
    candidates = sorted(name for name, status in enabled.items()
                        if name != ctx.region and status != 'not-opted-in')
    assert candidates, (
        f"no second region is enabled for this account besides {ctx.region!r}; DescribeRegions "
        f"returned {enabled!r}")

    second = None
    zone_addresses = None
    for name in candidates:
        addresses = _resolves(f'server.transfer.{name}.amazonaws.com')
        if addresses:
            second, zone_addresses = name, addresses
            break
    assert second is not None, (
        f"none of the enabled regions {candidates!r} publishes a Transfer SFTP endpoint zone, so "
        f"there is no second region to hold this server id against")
    assert enabled[second] != 'not-opted-in', (
        f"the derived second region {second!r} reads OptInStatus {enabled[second]!r}, so it is not "
        f"enabled for this account")

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)
    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_PAYLOAD)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    server_id = _create_server(ctx, transfer)
    _poll(lambda: transfer.describe_server(ServerId=server_id)['Server']['State'],
          lambda s: s == 'ONLINE', timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
          what=f'server {server_id} to reach ONLINE')

    user = ctx.unique_name('sim2real-region-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    own_host = f'{server_id}.server.transfer.{ctx.region}.amazonaws.com'
    foreign_host = f'{server_id}.server.transfer.{second}.amazonaws.com'

    _wait_for_ssh_banner(own_host, timeout_s=_ENDPOINT_TIMEOUT_S)

    # POSITIVE CONTROL: the server really serves SFTP under its own region's name, and the bytes
    # land in the backing store. Everything below is only meaningful because this works.
    transport, sftp = _open_sftp_when_ready(own_host, user, priv)
    try:
        sftp.put(local_up, f'/{bucket}/home/region.bin')
        with sftp.open(f'/{bucket}/home/region.bin', 'rb') as fh:
            served = fh.read()
    finally:
        sftp.close()
        transport.close()
    assert served == _PAYLOAD, (
        f"the SFTP read-back returned {len(served)!r} bytes with sha256 "
        f"{hashlib.sha256(served).hexdigest()!r}, uploaded {len(_PAYLOAD)!r} with "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")
    stored = s3.get_object(Bucket=bucket, Key='home/region.bin')['Body'].read()
    assert stored == _PAYLOAD, (
        f"S3 holds {len(stored)!r} bytes with sha256 {hashlib.sha256(stored).hexdigest()!r} for "
        f"the object the SFTP put created; uploaded {len(_PAYLOAD)!r} with "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    own_addresses = _resolves(own_host)
    assert own_addresses is not None, (
        f"{own_host!r} stopped resolving after serving an SFTP session over it")
    assert len(own_addresses) >= 1, (
        f"{own_host!r} resolved to an empty address set {own_addresses!r} after serving an SFTP "
        f"session over it")

    # EFFECT ABSENT, data plane: the same id under the derived second region's endpoint name does
    # not exist. The zone itself does -- `zone_addresses` above -- so the absent name is the server
    # id, not the region.
    foreign_addresses = _resolves(foreign_host)
    assert foreign_addresses is None, (
        f"{foreign_host!r} resolves to {foreign_addresses!r}, so the server minted in "
        f"{ctx.region!r} is addressable under {second!r} too; the region's own zone "
        f"server.transfer.{second}.amazonaws.com resolves to {zone_addresses!r} and "
        f"{own_host!r} to {own_addresses!r}")

    # EFFECT ABSENT, control plane: the same id in the second region is simply not there.
    foreign_transfer = ctx.client('transfer', region=second)
    code, message = _error(lambda: foreign_transfer.describe_server(ServerId=server_id))
    assert code == 'ResourceNotFoundException', (
        f"DescribeServer for {server_id!r} in {second!r} failed with {code!r}, not "
        f"ResourceNotFoundException")
    assert message == 'Unknown server', (
        f"DescribeServer for {server_id!r} in {second!r}: unexpected message {message!r}")
    assert server_id not in _server_ids(foreign_transfer), (
        f"{server_id!r} appears in ListServers for {second!r} although it was created in "
        f"{ctx.region!r}")

    # And it is still there in its own region: the assertions above are about the second region,
    # not about a server that quietly went away.
    assert server_id in _server_ids(transfer), (
        f"{server_id!r} is not in ListServers for its own region {ctx.region!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
