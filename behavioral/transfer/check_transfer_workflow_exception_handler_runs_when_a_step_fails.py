"""transfer-workflow-exception-handler-runs-when-a-step-fails."""
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
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "transfer-workflow-exception-handler-runs-when-a-step-fails"
GROUP = 'workflow-rejection'
SERVICES = ['transfer']

_PAYLOAD = b'sim2real exception-handler payload \x00\xff\n' * 64

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


def _exception_workflow_policy(bucket: str):
    """An ExecutionRole that may write ONLY under dest-ok/. Reading and deleting the source is
    allowed, so the DELETE in OnExceptionSteps can succeed while the COPY cannot."""
    return [
        {'Effect': 'Allow', 'Action': ['s3:ListBucket', 's3:GetBucketLocation'],
         'Resource': f'arn:aws:s3:::{bucket}'},
        {'Effect': 'Allow',
         'Action': ['s3:GetObject', 's3:GetObjectVersion', 's3:GetObjectTagging',
                    's3:DeleteObject'],
         'Resource': f'arn:aws:s3:::{bucket}/*'},
        {'Effect': 'Allow', 'Action': ['s3:PutObject', 's3:PutObjectTagging'],
         'Resource': f'arn:aws:s3:::{bucket}/dest-ok/*'},
    ]


def _make_workflow(ctx, transfer, bucket: str, dest_prefix: str) -> str:
    """A COPY into dest_prefix with a DELETE of the original as the only OnExceptionSteps entry."""
    workflow_id = transfer.create_workflow(
        # CreateWorkflow's Description is constrained to [\w- ]* -- '/' and '>' are both
        # rejected with a ValidationException, so the prefix is folded in bare.
        Description=f'sim2real {CHECK} {dest_prefix.strip(chr(47))}',
        Steps=[{'Type': 'COPY',
                'CopyStepDetails': {
                    'Name': 'sim2real-copy',
                    'DestinationFileLocation': {
                        'S3FileLocation': {'Bucket': bucket, 'Key': dest_prefix}},
                    'OverwriteExisting': 'TRUE',
                    'SourceFileLocation': '${original.file}'}}],
        OnExceptionSteps=[{'Type': 'DELETE',
                           'DeleteStepDetails': {'Name': 'sim2real-delete',
                                                 'SourceFileLocation': '${original.file}'}}],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['WorkflowId']
    ctx.on_cleanup(lambda: transfer.delete_workflow(WorkflowId=workflow_id))
    return workflow_id


def _settled(transfer, workflow_id: str, *, timeout_s, interval_s) -> None:
    """Wait until the workflow has no execution left in flight.

    On real AWS, ListExecutions and DescribeExecution expose an
    execution ONLY while its Status is IN_PROGRESS. Once it finishes it leaves ListExecutions
    entirely -- a probe saw 1 row, then 0 on all nine later polls -- and DescribeExecution answers
    ResourceNotFoundException 'Unknown execution' for that same id from then on. So neither the
    terminal ExecutionStatus nor the per-step Results are observable through this API, and an empty
    list is the only signal that the execution is over. That is the wait; the S3 state afterwards is
    the evidence.
    """
    def _count():
        rows = []
        for page in transfer.get_paginator('list_executions').paginate(WorkflowId=workflow_id):
            rows += page.get('Executions', [])
        return len(rows)

    _poll(_count, lambda n: n == 0, timeout_s=timeout_s, interval_s=interval_s,
          what=f'every execution of workflow {workflow_id} to finish and leave ListExecutions')


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A workflow whose COPY cannot write runs its OnExceptionSteps DELETE, leaving no copy and no
    source, while an identical workflow with a writable destination keeps the source and a
    byte-identical copy.
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
    user_role = _create_transfer_role(ctx, iam, _home_policy(bucket))
    exec_role = _create_transfer_role(ctx, iam, _exception_workflow_policy(bucket))

    wf_denied = _make_workflow(ctx, transfer, bucket, 'dest-denied/')
    wf_ok = _make_workflow(ctx, transfer, bucket, 'dest-ok/')
    assert wf_denied != wf_ok, "the two workflows collided"

    # Two servers, because WorkflowDetails is a SERVER-level setting. They are created together and
    # polled together so the run pays for one provisioning wait, not two. Registered after the
    # workflows so LIFO deletes the servers first -- an attached workflow cannot be deleted.
    server_denied = _create_server(ctx, transfer, WorkflowDetails={
        'OnUpload': [{'WorkflowId': wf_denied, 'ExecutionRole': exec_role}]})
    server_ok = _create_server(ctx, transfer, WorkflowDetails={
        'OnUpload': [{'WorkflowId': wf_ok, 'ExecutionRole': exec_role}]})

    def _online(server_id):
        return _poll(lambda: transfer.describe_server(ServerId=server_id)['Server']['State'],
                     lambda s: s == 'ONLINE', timeout_s=_ONLINE_TIMEOUT_S,
                     interval_s=_INTERVAL_S, what=f'server {server_id} to reach ONLINE')

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(_online, [server_denied, server_ok]))

    users = {}
    for label, server_id in (('denied', server_denied), ('ok', server_ok)):
        user = ctx.unique_name(f'sim2real-wfx-{label}-u-').replace('_', '-').lower()
        home = f'/{bucket}/source-{label}'
        _retry_on_iam_propagation(lambda sid=server_id, u=user, h=home: transfer.create_user(
            ServerId=sid, UserName=u, Role=user_role,
            HomeDirectory=h, HomeDirectoryType='PATH',
            SshPublicKeyBody=pub, Tags=[{'Key': 'sim2real', 'Value': CHECK}]))
        ctx.on_cleanup(lambda sid=server_id, u=user: transfer.delete_user(ServerId=sid, UserName=u))
        users[label] = user

    host_denied = f'{server_denied}.server.transfer.{ctx.region}.amazonaws.com'
    host_ok = f'{server_ok}.server.transfer.{ctx.region}.amazonaws.com'
    _wait_for_ssh_banner(host_denied, timeout_s=_ENDPOINT_TIMEOUT_S)
    _wait_for_ssh_banner(host_ok, timeout_s=_ENDPOINT_TIMEOUT_S)

    # POSITIVE CONTROL FIRST, so it doubles as the propagation barrier: until a workflow with a
    # writable destination demonstrably runs end to end, a missing copy proves nothing.
    rc_ok, _, err_ok = _sftp(ctx, workdir, host_ok, users['ok'], priv,
                             [f'put {local_up} survivor.bin', 'quit'])
    assert rc_ok == 0, f"the control upload failed: rc {rc_ok!r}, {err_ok[-600:]!r}"
    _settled(transfer, wf_ok, timeout_s=600.0, interval_s=5.0)
    # An empty ListExecutions is NOT the end of the work: the steps continue after the record
    # becomes invisible (the DELETE in the denied branch below lands seconds after it). So the
    # observable condition, not the invisible record, is what is waited on.
    _poll(lambda: _head_code(s3, bucket, 'dest-ok/survivor.bin'), lambda c: c == '200',
          timeout_s=300.0, interval_s=10.0,
          what="the writable COPY step's destination object to appear")

    control_copy = s3.get_object(Bucket=bucket, Key='dest-ok/survivor.bin')['Body'].read()
    assert control_copy == _PAYLOAD, (
        f"the writable COPY produced {len(control_copy)!r} bytes, uploaded {len(_PAYLOAD)!r}; "
        f"sha256 {hashlib.sha256(control_copy).hexdigest()!r} vs "
        f"{hashlib.sha256(_PAYLOAD).hexdigest()!r}")
    control_source = s3.get_object(Bucket=bucket, Key='source-ok/survivor.bin')['Body'].read()
    assert control_source == _PAYLOAD, (
        f"the successful workflow's source object is {len(control_source)!r} bytes, uploaded "
        f"{len(_PAYLOAD)!r} -- the exception handler must NOT have run on this branch")

    # BREAK EXACTLY ONE THING: the same upload, into the server whose workflow copies to a prefix
    # the ExecutionRole cannot write.
    rc, _, err = _sftp(ctx, workdir, host_denied, users['denied'], priv,
                       [f'put {local_up} doomed.bin', 'quit'])
    assert rc == 0, (
        f"the upload itself failed, so nothing below is about the workflow: rc {rc!r}, "
        f"{err[-600:]!r}")
    _settled(transfer, wf_denied, timeout_s=600.0, interval_s=5.0)

    # THE EFFECT OF THE EXCEPTION BRANCH: the source object goes away, because OnExceptionSteps ran.
    # Only that DELETE removes it -- the control branch above proves the workflow does NOT delete it
    # when the COPY succeeds. Polled, not read once: the DELETE lands seconds AFTER the
    # execution has already left ListExecutions, so a single read right after _settled sees the
    # object still there. Exhaustion of this bounded poll is a FAIL, and it names what it saw.
    _poll(lambda: _head_code(s3, bucket, 'source-denied/doomed.bin'), lambda c: c == '404',
          timeout_s=300.0, interval_s=10.0,
          what='the OnExceptionSteps DELETE to remove the uploaded source object')
    assert _head_code(s3, bucket, 'source-denied/doomed.bin') == '404', (
        f"the OnExceptionSteps DELETE did not remove the source object; the bucket holds "
        f"{sorted(_all_keys(s3, bucket))!r}")

    # AND THE COPY'S OWN EFFECT IS ABSENT: the denied destination gained nothing.
    denied_keys = _all_keys(s3, bucket, prefix='dest-denied/')
    assert denied_keys == set(), (
        f"the COPY step wrote to a prefix its ExecutionRole has no s3:PutObject for: "
        f"{sorted(denied_keys)!r}")

    assert _all_keys(s3, bucket) == {'source-ok/survivor.bin', 'dest-ok/survivor.bin'}, (
        f"the bucket holds {sorted(_all_keys(s3, bucket))!r}; only the control branch's source and "
        f"its copy should survive both uploads")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
