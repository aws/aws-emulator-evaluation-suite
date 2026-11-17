"""transfer-path-home-directory-is-no-jail-and-the-sibling-prefix-read-is-denied."""
from __future__ import annotations

import errno
import io
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "transfer-path-home-directory-is-no-jail-and-the-sibling-prefix-read-is-denied"
GROUP = 'sftp-rejection'
SERVICES = ['transfer']

# Two prefixes of ONE bucket this check creates, so every listing it asserts on is bounded by a
# namespace nothing else in the account can write to.
_OWN = 'own'
_OTHER = 'other'
_SECRET = b'sim2real-other-tenant-secret-' + bytes(range(32))
_MINE = b'sim2real-own-tenant-payload-' + bytes(range(32))

_ONLINE_TIMEOUT_S = 900.0
_SESSION_TIMEOUT_S = 420.0
_INTERVAL_S = 2.0


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A PATH home directory is a starting directory, not a jail: the user lists a sibling prefix,
    yet its get is refused SSH_FX_PERMISSION_DENIED and its put SSH_FX_NO_SUCH_FILE with the object
    unmodified, while a twin user whose role covers the prefix reads it: the role confines.
    """
    import paramiko

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key=f"{_OTHER}/secret.txt", Body=_SECRET)
    own_role = _create_role(ctx, bucket, _OWN)
    other_role = _create_role(ctx, bucket, _OTHER)

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-jail-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    own_key = paramiko.RSAKey.generate(2048)
    other_key = paramiko.RSAKey.generate(2048)
    own_user = ctx.unique_name("sim2realjailown")
    other_user = ctx.unique_name("sim2realjailoth")
    for user, role, prefix, pkey in ((own_user, own_role, _OWN, own_key),
                                     (other_user, other_role, _OTHER, other_key)):
        _retry_role_propagation(lambda user=user, role=role, prefix=prefix, pkey=pkey:
                                transfer.create_user(
                                    ServerId=server_id,
                                    UserName=user,
                                    Role=role,
                                    HomeDirectoryType="PATH",
                                    HomeDirectory=f"/{bucket}/{prefix}",
                                    SshPublicKeyBody=f"{pkey.get_name()} {pkey.get_base64()}",
                                ))
        ctx.on_cleanup(lambda user=user: transfer.delete_user(ServerId=server_id, UserName=user))

    _wait_for_server_state(transfer, server_id, "ONLINE", _ONLINE_TIMEOUT_S)

    host = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"
    transport = _connect(host, own_user, own_key, _SESSION_TIMEOUT_S)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)

        # --- positive control: the session works, inside its own home
        sftp.putfo(io.BytesIO(_MINE), "mine.bin")
        with sftp.open("mine.bin", "rb") as fh:
            mine = fh.read()
        assert mine == _MINE, (
            f"the user cannot even read its own upload: got {len(mine)} bytes, expected "
            f"{len(_MINE)}"
        )
        assert sftp.normalize(".") == f"/{bucket}/{_OWN}", (
            f"the session's working directory is {sftp.normalize('.')!r}, expected the PATH home "
            f"{'/' + bucket + '/' + _OWN!r}"
        )

        # --- half one: the namespace is NOT jailed. The sibling prefix's names are visible.
        top = sorted(sftp.listdir(f"/{bucket}"))
        assert top == [_OTHER, _OWN], (
            f"listing the bucket root from inside a PATH home returned {top!r}, expected "
            f"{[_OTHER, _OWN]!r} — a PATH home does not chroot the session"
        )
        sibling = sorted(sftp.listdir(f"/{bucket}/{_OTHER}"))
        assert sibling == ["secret.txt"], (
            f"listing the sibling prefix returned {sibling!r}, expected ['secret.txt'] — "
            f"s3:ListBucket is granted bucket-wide, so the names are readable"
        )

        # --- half two: every ACCESS to that prefix is refused, by both path forms
        for label, path in (("an absolute path", f"/{bucket}/{_OTHER}/secret.txt"),
                            ("a `..` traversal", f"../{_OTHER}/secret.txt")):
            denied = _sftp_error(lambda path=path: sftp.open(path, "rb").read(),
                                 f"a get of the sibling prefix by {label}")
            assert type(denied) is PermissionError and denied.errno == errno.EACCES, (
                f"the get by {label} raised {type(denied).__name__} errno {denied.errno!r}, "
                f"expected PermissionError errno {errno.EACCES} (SSH_FX_PERMISSION_DENIED)"
            )
            assert denied.strerror == "Access denied", (
                f"the get by {label} was refused with {denied.strerror!r}, expected 'Access denied'"
            )

        intruder = f"/{bucket}/{_OTHER}/intruder.txt"
        refused_put = _sftp_error(lambda: sftp.putfo(io.BytesIO(b"sim2real-intruder"), intruder),
                                  "a put into the sibling prefix")
        assert type(refused_put) is FileNotFoundError and refused_put.errno == errno.ENOENT, (
            f"the put into the sibling prefix raised {type(refused_put).__name__} errno "
            f"{refused_put.errno!r}, expected FileNotFoundError errno {errno.ENOENT} "
            f"(SSH_FX_NO_SUCH_FILE — the service reports a denied write as a missing path)"
        )
        assert refused_put.strerror == intruder, (
            f"the refused put names {refused_put.strerror!r}, expected the target path "
            f"{intruder!r}"
        )

        refused_rm = _sftp_error(lambda: sftp.remove(f"/{bucket}/{_OTHER}/secret.txt"),
                                 "a remove of the sibling prefix's object")
        assert type(refused_rm) is PermissionError and refused_rm.errno == errno.EACCES, (
            f"the remove raised {type(refused_rm).__name__} errno {refused_rm.errno!r}, expected "
            f"PermissionError errno {errno.EACCES}"
        )

        # --- the effect is ABSENT: the sibling prefix is exactly as it was
        keys = _all_keys(s3, bucket, f"{_OTHER}/")
        assert keys == [f"{_OTHER}/secret.txt"], (
            f"the sibling prefix now holds {keys!r}, expected only ['{_OTHER}/secret.txt'] — the "
            f"refused put must not have written anything"
        )
        secret = s3.get_object(Bucket=bucket, Key=f"{_OTHER}/secret.txt")["Body"].read()
        assert secret == _SECRET, (
            f"the sibling prefix's object holds {len(secret)} bytes, not the {len(_SECRET)} it was "
            f"seeded with — a refused session modified it"
        )
    finally:
        transport.close()

    # --- the second positive control: the refusal was the ROLE, not a missing object. A twin user
    # on the SAME server reads the very key the first user was refused.
    twin = _connect(host, other_user, other_key, _SESSION_TIMEOUT_S)
    try:
        twin_sftp = paramiko.SFTPClient.from_transport(twin)
        with twin_sftp.open("secret.txt", "rb") as fh:
            read_back = fh.read()
        assert read_back == _SECRET, (
            f"the user whose role covers the prefix read {len(read_back)} bytes, expected the "
            f"{len(_SECRET)} seeded — the object the first user was refused must be readable by it"
        )
    finally:
        twin.close()


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
    """An authenticated paramiko Transport, retrying only the endpoint's warm-up."""
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
    bucket = ctx.unique_name("sim2real-transfer-jail-")
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
    """A role Transfer can assume: ListBucket over the whole bucket (which is what makes the
    sibling prefix's NAMES visible), object access over exactly one prefix."""
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-transfer-jail-{prefix}-")
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
