"""transfer-ssh-key-of-one-user-is-rejected-for-another-user-on-the-same-server."""
from __future__ import annotations

import io
import json
import time

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing
from botocore.exceptions import ClientError

CHECK = "transfer-ssh-key-of-one-user-is-rejected-for-another-user-on-the-same-server"
GROUP = 'sftp-rejection'
SERVICES = ['transfer']

# Two homes in one bucket, and ONE role shared by both users: the only thing that differs between
# the two identities is the SSH key, which is what makes the refusal attributable to the key.
_HOME_A = 'usera'
_HOME_B = 'userb'
_BYTES_A = b'sim2real-user-a-payload-' + bytes(range(32))
_BYTES_B = b'sim2real-user-b-payload-' + bytes(reversed(range(32)))

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
    """The SERVICE_MANAGED identity provider binds a key to one user, not the server: each of two
    users on one server authenticates with its own key, each key is refused for the other user and
    writes nothing, and the first user's key still works afterwards.
    """
    try:
        import paramiko
    except ImportError as exc:
        raise RequiredToolMissing(["paramiko"], "module") from exc

    transfer = ctx.client("transfer")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket)

    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "sim2real", "Value": CHECK},
              {"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-keyscope-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    key_a = paramiko.RSAKey.generate(2048)
    key_b = paramiko.RSAKey.generate(2048)
    user_a = ctx.unique_name("sim2realkeya")
    user_b = ctx.unique_name("sim2realkeyb")
    for user, home, pkey in ((user_a, _HOME_A, key_a), (user_b, _HOME_B, key_b)):
        _retry_role_propagation(lambda user=user, home=home, pkey=pkey: transfer.create_user(
            ServerId=server_id,
            UserName=user,
            Role=role_arn,
            HomeDirectoryType="PATH",
            HomeDirectory=f"/{bucket}/{home}",
            SshPublicKeyBody=f"{pkey.get_name()} {pkey.get_base64()}",
        ))
        ctx.on_cleanup(lambda user=user: transfer.delete_user(ServerId=server_id, UserName=user))

    _wait_for_server_state(transfer, server_id, "ONLINE", _ONLINE_TIMEOUT_S)
    host = f"{server_id}.server.transfer.{ctx.region}.amazonaws.com"

    # --- positive controls FIRST, so a later refusal cannot be a warm-up failure wearing an
    # authentication message: each user authenticates with its OWN key and uploads.
    for user, home, pkey, payload in ((user_a, _HOME_A, key_a, _BYTES_A),
                                      (user_b, _HOME_B, key_b, _BYTES_B)):
        transport = _connect(host, user, pkey, _SESSION_TIMEOUT_S)
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.putfo(io.BytesIO(payload), "own.bin")
        finally:
            transport.close()
        landed = s3.get_object(Bucket=bucket, Key=f"{home}/own.bin")["Body"].read()
        assert landed == payload, (
            f"{user}'s own upload holds {len(landed)} bytes at {home}/own.bin, expected "
            f"{len(payload)} — the positive control must land before any refusal means anything"
        )

    # --- break exactly one thing: the key offered belongs to the OTHER user of this server
    for user, other_key, owner in ((user_b, key_a, user_a), (user_a, key_b, user_b)):
        refused = _auth_failure(host, user, other_key, owner)
        assert type(refused) is paramiko.AuthenticationException, (
            f"offering {owner}'s key as {user} raised {type(refused).__name__}, expected "
            f"AuthenticationException"
        )
        assert str(refused) == "Authentication failed.", (
            f"the refusal read {str(refused)!r}, expected 'Authentication failed.' — the SSH "
            f"userauth exchange must reject the key outright"
        )

    # --- the effect is ABSENT: the refused sessions wrote nothing anywhere in the bucket
    keys = _all_keys(s3, bucket, "")
    assert keys == [f"{_HOME_A}/own.bin", f"{_HOME_B}/own.bin"], (
        f"the bucket holds {keys!r}, expected only the two objects the authenticated sessions "
        f"uploaded — a refused authentication must not write"
    )

    # --- and the refusals did not lock the legitimate key out
    transport = _connect(host, user_a, key_a, _SESSION_TIMEOUT_S)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
        listed = sorted(sftp.listdir("."))
        assert listed == ["own.bin"], (
            f"after two refused attempts the legitimate key listed {listed!r}, expected "
            f"['own.bin'] — the failures must not have affected the user's own access"
        )
    finally:
        transport.close()


# ===== helpers =====
def _auth_failure(host: str, username: str, pkey, owner: str):
    """The AuthenticationException one attempt raised, with the two other outcomes classified.

    A server that ACCEPTS the key is the over-permissiveness this check exists to catch, so it
    raises rather than returning a sentinel; an endpoint-level SSHException is reported as itself
    rather than being allowed to read as an authentication decision.
    """
    import paramiko

    transport = _transport(host, 120.0)
    try:
        transport.connect(username=username, pkey=pkey)
    except paramiko.AuthenticationException as exc:
        assert not transport.is_authenticated(), (
            f"the transport for {username!r} reports itself authenticated after raising "
            f"{exc!r}"
        )
        return exc
    except paramiko.SSHException as exc:
        raise AssertionError(f"the attempt as {username!r} with {owner}'s key failed for a reason "
                             f"that is NOT an authentication decision: {exc!r}")
    else:
        raise AssertionError(f"the server authenticated {username!r} with the key registered for "
                             f"{owner!r}; a SERVICE_MANAGED key must be scoped to its own user")
    finally:
        transport.close()


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
    bucket = ctx.unique_name("sim2real-transfer-keyscope-")
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


def _create_role(ctx, bucket: str) -> str:
    """One role, shared by both users, covering the whole bucket: the identities differ ONLY in
    their SSH key, so a refusal cannot be authorization wearing an authentication message."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-keyscope-role-")
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
             "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
    return arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, delay_s: float = 2.0):
    """Retry a call that depends on a just-created IAM role on the codes Transfer answers until
    the role is assumable: IAM exposes no condition to poll, so this retry is the wait."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "InvalidRequestException"):
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise AssertionError(f"CreateUser never accepted the freshly created role: {last_exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
