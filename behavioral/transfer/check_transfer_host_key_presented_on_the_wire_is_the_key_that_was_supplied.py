"""transfer-host-key-presented-on-the-wire-is-the-key-that-was-supplied."""
from __future__ import annotations

import base64
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

CHECK = "transfer-host-key-presented-on-the-wire-is-the-key-that-was-supplied"
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

_PAYLOAD = b'sim2real host-key payload \x00\xff\r\n' * 128

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
    # `extra` goes BEFORE the built-in `-o` defaults: OpenSSH keeps the first value it sees for a
    # repeated setting and silently drops later ones (verified with `ssh -G`), so a caller's own
    # `-o UserKnownHostsFile=...` must precede this function's default of `/dev/null` or it is
    # never honoured and the client always reports writing to /dev/null instead.
    argv = ['/usr/bin/sftp', '-b', batch, '-i', priv,
            *extra,
            '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'BatchMode=yes',
            '-o', 'NumberOfPasswordPrompts=0',
            '-o', 'PreferredAuthentications=publickey',
            '-o', 'ConnectTimeout=30',
            f'{user}@{host}']
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


def _openssh_sha256_fingerprint(pub_blob_b64: str) -> str:
    """OpenSSH's SHA256 fingerprint of a public key, recomputed from the key's own wire bytes.

    This is the B3 leg: the value derives from bytes ssh-keygen produced in THIS run, so no
    recorded HTTP exchange can carry it, and it follows the target rather than a stored literal.
    Padding is stripped because OpenSSH prints the digest unpadded.
    """
    blob = base64.b64decode(pub_blob_b64)
    return base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def _pub_blob(pub_body: str) -> str:
    """The base64 key material out of an `ssh-rsa AAAA... comment` line."""
    fields = pub_body.split()
    assert len(fields) >= 2, f"unparseable public key line: {pub_body!r}"
    return fields[1]


def _normalise_service_fingerprint(value: str) -> str:
    """Strip an OpenSSH-style algorithm prefix and base64 padding, so the comparison is about the
    digest and not about how the service chose to decorate it."""
    return value.split('SHA256:')[-1].strip().rstrip('=')


def _known_hosts_fingerprints(path: str) -> list:
    """Every host key OpenSSH recorded in *path*, as recomputed SHA256 fingerprints.

    Parsed positionally and tolerant of a hashed (|1|...) hostname field, because which of those
    the client writes is a client detail and not the property under test. Raises if nothing parses,
    rather than returning an empty list that an assertion could read as agreement.
    """
    out = []
    with open(path) as fh:
        for line in fh:
            fields = line.split()
            if len(fields) < 3 or not fields[1].startswith(('ssh-', 'ecdsa-', 'rsa-')):
                continue
            out.append((fields[1], _openssh_sha256_fingerprint(fields[2])))
    assert out, (
        f"OpenSSH wrote no parseable host key line into {path!r}; contents "
        f"{open(path).read()[:400]!r}")
    return out


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Transfer server presents in the SSH handshake the host key it was given: the SHA256
    fingerprint of the generated RSA key matches the wire key and DescribeServer/DescribeHostKey,
    and after importing an ed25519 key a client selecting each algorithm is offered that key.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    account = ctx.client('sts').get_caller_identity()['Account']
    assert account.isdigit() and len(account) == 12, (
        f"GetCallerIdentity returned a malformed account id {account!r}")

    workdir = _workdir(ctx)
    host_priv, host_pub = _keygen(workdir, 'server-host-key-rsa', kind='rsa')
    ed_priv, ed_pub = _keygen(workdir, 'server-host-key-ed25519', kind='ed25519')
    user_priv, user_pub = _keygen(workdir, 'user-key')

    rsa_expected = _openssh_sha256_fingerprint(_pub_blob(host_pub))
    ed_expected = _openssh_sha256_fingerprint(_pub_blob(ed_pub))
    assert rsa_expected != ed_expected, "the two host keys hashed identically"

    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_PAYLOAD)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    # The server is given OUR key, so there is exactly one RSA host key and its provenance is known.
    server_id = _create_server(ctx, transfer, HostKey=open(host_priv).read())
    described = _online(ctx, transfer, server_id)

    # The control plane's claim about the fingerprint. Normalised, because the decoration is not
    # the property under test; the WIRE comparison below is the one that does not depend on it.
    reported = described.get('HostKeyFingerprint')
    assert reported, f"DescribeServer reported no HostKeyFingerprint at all: {described!r}"
    assert _normalise_service_fingerprint(reported) == rsa_expected, (
        f"DescribeServer reports host key fingerprint {reported!r}, but the key this check "
        f"supplied hashes to SHA256:{rsa_expected} -- so the server is not holding the key it was "
        f"given")

    user = ctx.unique_name('sim2real-hostkey-u-').replace('_', '-').lower()
    _retry_on_iam_propagation(lambda: transfer.create_user(
        ServerId=server_id, UserName=user, Role=role_arn,
        HomeDirectory=f'/{bucket}/home', HomeDirectoryType='PATH',
        SshPublicKeyBody=user_pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user))

    host = _host(ctx, server_id)
    _wait_for_ssh_banner(host, timeout_s=_ENDPOINT_TIMEOUT_S)

    # ---- POSITIVE CONTROL FIRST, and the propagation barrier: a real session works, and the host
    # key it recorded on the wire is the one we supplied.
    rsa_kh = os.path.join(workdir, 'known-hosts-rsa')
    ok_rc, _ok_out, ok_err = _sftp(
        ctx, workdir, host, user, user_priv, [f'put {local_up} hostkey.bin', 'quit'],
        extra=('-o', f'UserKnownHostsFile={rsa_kh}',
               '-o', 'HostKeyAlgorithms=rsa-sha2-256,rsa-sha2-512,ssh-rsa'))
    assert ok_rc == 0, (
        f"the authorised session failed, so nothing below can be attributed to the host key: "
        f"rc {ok_rc!r}, stderr {ok_err[-600:]!r}")
    landed = s3.get_object(Bucket=bucket, Key='home/hostkey.bin')['Body'].read()
    assert landed == _PAYLOAD, (
        f"the upload landed as {len(landed)!r} bytes with sha256 "
        f"{hashlib.sha256(landed).hexdigest()!r}, sent {len(_PAYLOAD)!r} with sha256 "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    on_wire = _known_hosts_fingerprints(rsa_kh)
    wire_fingerprints = {fp for _alg, fp in on_wire}
    assert wire_fingerprints == {rsa_expected}, (
        f"the SSH handshake presented host key fingerprints {sorted(wire_fingerprints)!r}, but the "
        f"key supplied to CreateServer hashes to {rsa_expected!r}; recorded lines {on_wire!r}")

    # ---- A SECOND ACTIVE HOST KEY of a different algorithm, imported after the fact.
    imported = transfer.import_host_key(
        ServerId=server_id, HostKeyBody=open(ed_priv).read(),
        Description='sim2real ed25519 host key',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    host_key_id = imported['HostKeyId']
    ctx.on_cleanup(lambda: transfer.delete_host_key(ServerId=server_id, HostKeyId=host_key_id))

    ed_described = transfer.describe_host_key(
        ServerId=server_id, HostKeyId=host_key_id)['HostKey']
    assert _normalise_service_fingerprint(ed_described['HostKeyFingerprint']) == ed_expected, (
        f"DescribeHostKey reports {ed_described['HostKeyFingerprint']!r} for the imported ed25519 "
        f"key, which hashes to SHA256:{ed_expected}")

    # ---- TERMINAL ASSERTION, on the wire: the client selecting each algorithm is presented that
    # algorithm's key. Both sides of this comparison are computed in this file from bytes generated
    # in this run, so it holds regardless of how the service formats a fingerprint.
    selections = {
        'ssh-ed25519': ed_expected,
        'rsa-sha2-256': rsa_expected,
    }
    for algorithm, expected in selections.items():
        kh = os.path.join(workdir, f'known-hosts-{algorithm}')
        rc, _out, err = _poll(
            lambda a=algorithm, k=kh: _sftp(
                ctx, workdir, host, user, user_priv, ['pwd', 'quit'],
                extra=('-o', f'UserKnownHostsFile={k}', '-o', f'HostKeyAlgorithms={a}')),
            lambda triple: triple[0] == 0,
            timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=10.0,
            what=f'the server to accept a handshake pinned to host key algorithm {algorithm}')
        del rc, err
        seen = _known_hosts_fingerprints(kh)
        assert {fp for _alg, fp in seen} == {expected}, (
            f"pinning HostKeyAlgorithms={algorithm} presented {sorted(seen)!r}, expected exactly "
            f"the fingerprint of the {algorithm} key this check supplied ({expected!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
