"""transfer-sftp-rename-then-remove-moves-and-deletes-the-backing-s3-object."""
from __future__ import annotations

import errno
import io
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "transfer-sftp-rename-then-remove-moves-and-deletes-the-backing-s3-object"
GROUP = 'sftp-data-plane'
SERVICES = ['transfer']

# The home prefix this check occupies inside its OWN bucket, so every listing it asserts on is
# bounded by a namespace nothing else can write to -- a concurrent run cannot make "exactly
# these keys" wrong.
_HOME = 'home'
_PAYLOAD = bytes(bytearray(range(256)) * 32) + b'\r\n\x00sim2real\x00\r\n'

_ONLINE_TIMEOUT_S = 900.0
_SESSION_TIMEOUT_S = 420.0
_INTERVAL_S = 2.0


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """SFTP RENAME and REMOVE move and delete the backing S3 object: the new key holds the exact
    bytes with Transfer's writer attribution while the old key is gone, and a remove empties the home
    prefix on both the SFTP and S3 listings.
    """
    import paramiko

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket, _HOME)

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-mutate-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    key = paramiko.RSAKey.generate(2048)
    username = ctx.unique_name("sim2realmutate")
    _retry_role_propagation(lambda: transfer.create_user(
        ServerId=server_id,
        UserName=username,
        Role=role_arn,
        HomeDirectoryType="PATH",
        HomeDirectory=f"/{bucket}/{_HOME}",
        SshPublicKeyBody=f"{key.get_name()} {key.get_base64()}",
    ))
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=username))

    _wait_for_server_state(transfer, server_id, "ONLINE", _ONLINE_TIMEOUT_S)

    host = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    transport = _connect(host, username, key, _SESSION_TIMEOUT_S)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)

        # --- the upload, as the customer sees it and as S3 sees it
        sftp.putfo(io.BytesIO(_PAYLOAD), "payload.bin")
        listed = {a.filename: a.st_size for a in sftp.listdir_attr(".")}
        assert listed == {"payload.bin": len(_PAYLOAD)}, (
            f"after one put the SFTP home listing was {listed!r}, expected exactly "
            f"{{'payload.bin': {len(_PAYLOAD)}}}"
        )
        with sftp.open("payload.bin", "rb") as fh:
            got = fh.read()
        assert got == _PAYLOAD, (
            f"the SFTP get returned {len(got)} bytes (sha-prefix {got[:16]!r}), not the "
            f"{len(_PAYLOAD)} bytes uploaded (prefix {_PAYLOAD[:16]!r})"
        )

        head = s3.head_object(Bucket=bucket, Key=f"{_HOME}/payload.bin")
        assert head["ContentLength"] == len(_PAYLOAD), (
            f"the mapped key {_HOME}/payload.bin is {head['ContentLength']} bytes, expected "
            f"{len(_PAYLOAD)}"
        )
        body = s3.get_object(Bucket=bucket, Key=f"{_HOME}/payload.bin")["Body"].read()
        assert body == _PAYLOAD, (
            f"the object at {_HOME}/payload.bin holds {len(body)} bytes that differ from the "
            f"{len(_PAYLOAD)} uploaded over SFTP"
        )
        meta = head.get("Metadata", {})
        assert meta.get("user-agent") == "AWSTransfer", (
            f"the object's user-agent metadata is {meta.get('user-agent')!r}, not 'AWSTransfer' — "
            f"nothing attributes this object to the Transfer server that wrote it"
        )
        assert meta.get("user-agent-id") == f"{username}@{server_id}", (
            f"the object's user-agent-id is {meta.get('user-agent-id')!r}, expected "
            f"{username + '@' + server_id!r}"
        )

        # --- RENAME: the new key holds the bytes, the old key is gone
        sftp.rename("payload.bin", "moved.bin")
        listed = sorted(sftp.listdir("."))
        assert listed == ["moved.bin"], (
            f"after the rename the SFTP home listing was {listed!r}, expected ['moved.bin'] — the "
            f"old name must not survive a rename"
        )
        gone = _sftp_error(lambda: sftp.stat("payload.bin"), "stat of the pre-rename name")
        assert type(gone) is FileNotFoundError and gone.errno == errno.ENOENT, (
            f"stat of the pre-rename name raised {type(gone).__name__} errno {gone.errno!r}, "
            f"expected FileNotFoundError errno {errno.ENOENT}"
        )
        with sftp.open("moved.bin", "rb") as fh:
            moved = fh.read()
        assert moved == _PAYLOAD, (
            f"the renamed file returned {len(moved)} bytes; a rename must not alter content "
            f"({len(_PAYLOAD)} bytes uploaded)"
        )
        body = s3.get_object(Bucket=bucket, Key=f"{_HOME}/moved.bin")["Body"].read()
        assert body == _PAYLOAD, (
            f"the object at the renamed key {_HOME}/moved.bin holds {len(body)} bytes, not the "
            f"{len(_PAYLOAD)} that were uploaded"
        )
        code = _s3_error_code(lambda: s3.head_object(Bucket=bucket, Key=f"{_HOME}/payload.bin"),
                             "head of the pre-rename key")
        assert code == "404", (
            f"the pre-rename key {_HOME}/payload.bin answered {code!r}, expected '404' — S3 has no "
            f"rename, so the service must have deleted the source object, not merely copied it"
        )
        keys = _all_keys(s3, bucket, f"{_HOME}/")
        assert keys == [f"{_HOME}/moved.bin"], (
            f"after the rename the home prefix holds {keys!r}, expected exactly "
            f"['{_HOME}/moved.bin'] — a rename must leave one object, not two"
        )

        # --- REMOVE: gone from the session and from the bucket
        sftp.remove("moved.bin")
        listed = sorted(sftp.listdir("."))
        assert listed == [], (
            f"after the remove the SFTP home listing was {listed!r}, expected it to be empty"
        )
        gone = _sftp_error(lambda: sftp.stat("moved.bin"), "stat of the removed name")
        assert type(gone) is FileNotFoundError and gone.errno == errno.ENOENT, (
            f"stat of the removed name raised {type(gone).__name__} errno {gone.errno!r}, "
            f"expected FileNotFoundError errno {errno.ENOENT}"
        )
        code = _s3_error_code(lambda: s3.head_object(Bucket=bucket, Key=f"{_HOME}/moved.bin"),
                             "head of the removed key")
        assert code == "404", (
            f"the removed key {_HOME}/moved.bin answered {code!r}, expected '404' — an SFTP remove "
            f"must delete the backing object"
        )
        keys = _all_keys(s3, bucket, f"{_HOME}/")
        assert keys == [], (
            f"after the remove the home prefix still holds {keys!r}, expected nothing"
        )
    finally:
        transport.close()


# ===== helpers =====
def _transport(host: str, timeout_s: float):
    """A TCP transport to the server's SSH endpoint, retrying while the endpoint warms up.

    `paramiko.Transport((host, 22))` resolves the name itself, so DNS failure lands in the
    CONSTRUCTOR: a server that reports ONLINE can take another minute before
    ``<id>.server.transfer.<region>.amazonaws.com`` resolves at all, and that is warm-up, not a
    fidelity signal.
    """
    import socket

    import paramiko

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return paramiko.Transport((host, 22))  # customer-built AWS host
        except (socket.error, paramiko.SSHException, EOFError) as exc:
            last_exc = exc
            time.sleep(_INTERVAL_S)
    raise AssertionError(f"the SSH endpoint {host} never resolved or accepted a connection within "
                        f"{timeout_s}s: {last_exc!r}")


def _connect(host: str, username: str, pkey, timeout_s: float):
    """An authenticated paramiko Transport, retrying only the endpoint's warm-up.

    An AuthenticationException is re-raised immediately: it is a decision the server made, and
    retrying it would let an authentication failure wear a "could not connect" message.
    """
    import socket

    import paramiko

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        transport = _transport(host, max(60.0, deadline - time.monotonic()))
        try:
            transport.connect(username=username, pkey=pkey)
            return transport
        except paramiko.AuthenticationException:
            transport.close()
            raise
        except (socket.error, paramiko.SSHException, EOFError) as exc:
            transport.close()
            last_exc = exc
            time.sleep(_INTERVAL_S)
    raise AssertionError(f"no SFTP session to {host} as {username!r} within {timeout_s}s; the "
                        f"server is ONLINE but its SSH endpoint never served us: {last_exc!r}")


def _sftp_error(fn, what: str) -> OSError:
    """The OSError an SFTP call raised. A call that SUCCEEDS is the strongest possible signal of
    over-permissiveness, so it raises here rather than returning a sentinel."""
    try:
        fn()
    except OSError as exc:
        return exc
    raise AssertionError(f"{what} succeeded; real AWS refuses it")


def _s3_error_code(fn, what: str) -> str:
    """The S3 error code a call raised. A call that succeeds raises, never returns a falsy code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"{what} succeeded; the object should not exist")


def _all_keys(s3, bucket: str, prefix: str) -> list[str]:
    """Every key under ``prefix``, paginated — one page is not a listing."""
    keys: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _wait_for_server_state(transfer, server_id: str, target: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state == target:
            return
        if state.endswith("_FAILED"):
            raise AssertionError(f"server {server_id} entered {state}, never reached {target}")
        time.sleep(_INTERVAL_S)
    raise AssertionError(f"server {server_id} never reached {target} within {timeout_s}s, "
                        f"last seen {state!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-transfer-mutate-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)

    def _cleanup() -> None:
        keys = _all_keys(s3, bucket, "")
        for i in range(0, len(keys), 1000):
            failed = s3.delete_objects(Bucket=bucket,
                              Delete={"Objects": [{"Key": k} for k in keys[i:i + 1000]]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_role(ctx, bucket: str, prefix: str) -> str:
    """A role Transfer can assume, allowed to read and write exactly one prefix of one bucket."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-mutate-role-")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=name, PolicyName="s3-home")
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(RoleName=name, PolicyName="s3-home", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
             "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow",
             "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:GetObjectVersion"],
             "Resource": f"arn:aws:s3:::{bucket}/{prefix}/*"}]}))
    return arn


def _retry_role_propagation(fn, attempts: int = 10, delay_s: float = 5.0):
    """Retry a call that depends on a just-created IAM role through IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise AssertionError(f"CreateUser never accepted the freshly created role: {last_exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
