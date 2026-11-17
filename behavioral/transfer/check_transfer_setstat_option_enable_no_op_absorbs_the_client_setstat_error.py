"""transfer-setstat-option-enable-no-op-absorbs-the-client-setstat-error."""
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

CHECK = "transfer-setstat-option-enable-no-op-absorbs-the-client-setstat-error"
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

_PAYLOAD = b'sim2real setstat payload \x00\xff\r\n' * 128

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


def _setstat_refused(err: str) -> bool:
    """Did the server refuse the client's SETSTAT/FSETSTAT?

    MEASURED on real AWS: a Transfer server with SetStatOption=DEFAULT refuses `put -p`'s FSETSTAT
    with stderr "remote fsetstat: Operation unsupported" -- but OpenSSH's sftp client treats that
    refusal as NON-FATAL to the put (it is a post-upload attribute-preservation step, not the
    transfer itself) and still exits 0. So the exit code carries no signal here; only stderr does.
    Matched on 'setstat' (the shared substring of the SETSTAT and FSETSTAT wordings) AND 'operation
    unsupported' (the server's real wording) together, tighter than either alone.
    """
    lowered = err.lower()
    return 'setstat' in lowered and 'operation unsupported' in lowered


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """SetStatOption changes what an SFTP client is told: two servers differing only in that enum
    both accept a plain put, but `put -p` (SETSTAT) is refused by the DEFAULT server and absorbed by the
    ENABLE_NO_OP one, with the bytes landing in S3 either way.
    """
    require_tools("ssh-keygen", "sftp")
    transfer = ctx.client('transfer')
    s3 = ctx.client('s3')
    iam = ctx.client('iam')

    account = ctx.client('sts').get_caller_identity()['Account']
    assert account.isdigit() and len(account) == 12, (
        f"GetCallerIdentity returned a malformed account id {account!r}")

    workdir = _workdir(ctx)
    priv, pub = _keygen(workdir)
    local_up = os.path.join(workdir, 'upload.bin')
    with open(local_up, 'wb') as fh:
        fh.write(_PAYLOAD)

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_transfer_role(ctx, iam, _home_policy(bucket))

    # Both servers first, so they provision concurrently: waiting for one and then creating the
    # other would double the dominant cost of this check.
    servers = {
        'default': _create_server(ctx, transfer,
                                  ProtocolDetails={'SetStatOption': 'DEFAULT'}),
        'noop': _create_server(ctx, transfer,
                               ProtocolDetails={'SetStatOption': 'ENABLE_NO_OP'}),
    }
    assert servers['default'] != servers['noop'], "the two servers collided"

    users = {}
    hosts = {}
    for label, server_id in servers.items():
        described = _online(ctx, transfer, server_id)
        # A cheap cross-check, NOT the verdict: the enum the control plane admits to holding. The
        # verdict is what the SSH client is told, below.
        # A cheap configuration cross-check, NOT the verdict -- the verdict is what the SSH client
        # is told, below. The two arms are asserted ASYMMETRICALLY on purpose: a service is free to
        # omit a field whose value is the default, so the DEFAULT arm accepts absence, while
        # ENABLE_NO_OP is non-default and must be echoed. Demanding a literal 'DEFAULT' echo would
        # make this fail against a correct target that simply omits it.
        stored = described.get('ProtocolDetails', {}).get('SetStatOption')
        if label == 'noop':
            assert stored == 'ENABLE_NO_OP', (
                f"noop: DescribeServer reports SetStatOption {stored!r}, expected 'ENABLE_NO_OP'; "
                f"the rest of this check would be asserting the wrong configuration")
        else:
            assert stored in (None, 'DEFAULT'), (
                f"default: DescribeServer reports SetStatOption {stored!r}, expected 'DEFAULT' or "
                f"the field to be absent; this server is not configured as this check requires")

        user = ctx.unique_name(f'sim2real-ss-{label}-u-').replace('_', '-').lower()
        # label bound as a default arg, not captured: a closure over the loop variable is correct
        # only while the call is immediate, and that is too fragile to rely on.
        _retry_on_iam_propagation(
            lambda sid=server_id, u=user, lb=label: transfer.create_user(
                ServerId=sid, UserName=u, Role=role_arn,
                HomeDirectory=f'/{bucket}/{lb}', HomeDirectoryType='PATH',
                SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
        ctx.on_cleanup(lambda sid=server_id, u=user: transfer.delete_user(ServerId=sid, UserName=u))
        users[label] = user
        hosts[label] = _host(ctx, server_id)
        _wait_for_ssh_banner(hosts[label], timeout_s=_ENDPOINT_TIMEOUT_S)

    # ---- POSITIVE CONTROL ON BOTH SERVERS: a plain put, which issues no SETSTAT, must succeed
    # everywhere. Without this leg a target that refuses every upload scores green below.
    for label in ('default', 'noop'):
        rc, _out, err = _sftp(ctx, workdir, hosts[label], users[label], priv,
                             [f'put {local_up} plain.bin', 'quit'])
        assert rc == 0, (
            f"{label}: a plain put (no SETSTAT) failed, so nothing below can be attributed to "
            f"SetStatOption: rc {rc!r}, stderr {err[-600:]!r}")
        body = s3.get_object(Bucket=bucket, Key=f'{label}/plain.bin')['Body'].read()
        assert body == _PAYLOAD, (
            f"{label}: the plain upload landed as {len(body)!r} bytes with sha256 "
            f"{hashlib.sha256(body).hexdigest()!r}, sent {len(_PAYLOAD)!r} with sha256 "
            f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")

    # ---- BREAK EXACTLY ONE THING: the identical command, now attribute-preserving, on two
    # servers whose only difference is the enum.
    results = {}
    for label in ('default', 'noop'):
        results[label] = _sftp(ctx, workdir, hosts[label], users[label], priv,
                               [f'put -p {local_up} preserved.bin', 'quit'])

    d_rc, _d_out, d_err = results['default']
    n_rc, _n_out, n_err = results['noop']

    assert d_rc == 0, (
        f"SetStatOption=DEFAULT: the attribute-preserving put itself must still succeed even "
        f"when the server refuses the FSETSTAT -- the refusal is non-fatal to the client, so a "
        f"nonzero exit here means something else broke: rc {d_rc!r}, stderr {d_err[-800:]!r}")
    assert _setstat_refused(d_err), (
        f"SetStatOption=DEFAULT did not surface a SETSTAT/FSETSTAT refusal to the client: "
        f"rc {d_rc!r}, stderr {d_err[-800:]!r}")
    assert not _setstat_refused(n_err), (
        f"SetStatOption=ENABLE_NO_OP still surfaced a SETSTAT refusal, so the option did not "
        f"absorb it: rc {n_rc!r}, stderr {n_err[-800:]!r}")
    assert n_rc == 0, (
        f"SetStatOption=ENABLE_NO_OP: the attribute-preserving put exited {n_rc!r}, expected 0; "
        f"stderr {n_err[-800:]!r}")

    # ---- A SECOND, INDEPENDENT SETSTAT LEG that does not depend on `put -p`'s internals: sftp's
    # `chmod` is a SETSTAT on an existing remote file. Same polarity, same two servers.
    c_rc, _c_out, c_err = _sftp(ctx, workdir, hosts['default'], users['default'], priv,
                                ['chmod 644 plain.bin', 'quit'])
    cn_rc, _cn_out, cn_err = _sftp(ctx, workdir, hosts['noop'], users['noop'], priv,
                                   ['chmod 644 plain.bin', 'quit'])
    assert _setstat_refused(c_err), (
        f"an explicit chmod (a SETSTAT on an existing file) must be refused under DEFAULT: "
        f"rc {c_rc!r} stderr {c_err[-300:]!r}")
    assert not _setstat_refused(cn_err), (
        f"an explicit chmod must be absorbed under ENABLE_NO_OP: "
        f"rc {cn_rc!r} stderr {cn_err[-300:]!r}")

    # ---- TERMINAL READ at the destination, through a different operation than the SFTP put: the
    # bytes landed on BOTH servers. Asserted explicitly because the docs say the SETSTAT error
    # occurs "even when the file is otherwise successfully uploaded" -- the object is NOT the
    # discriminator here, and a future reader must not think it is.
    for label in ('default', 'noop'):
        preserved = s3.get_object(Bucket=bucket, Key=f'{label}/preserved.bin')['Body'].read()
        assert preserved == _PAYLOAD, (
            f"{label}: the attribute-preserving upload did not land byte-identically -- "
            f"{len(preserved)!r} bytes with sha256 "
            f"{hashlib.sha256(preserved).hexdigest()!r}, sent {len(_PAYLOAD)!r} with sha256 "
            f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")
        keys = _all_keys(s3, bucket, prefix=f'{label}/')
        assert keys == {f'{label}/plain.bin', f'{label}/preserved.bin'}, (
            f"{label}: expected exactly the two uploaded keys under the prefix, got "
            f"{sorted(keys)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
