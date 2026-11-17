"""transfer-sftp-rename-onto-an-existing-name-is-rejected-and-clobbers-nothing."""
from __future__ import annotations

import io
import json
import time

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing
from botocore.exceptions import ClientError

CHECK = "transfer-sftp-rename-onto-an-existing-name-is-rejected-and-clobbers-nothing"
GROUP = 'sftp-rejection'
SERVICES = ['transfer']

_HOME = 'home'
_BYTES_A = b'sim2real-source-object-' + bytes(range(64))
_BYTES_B = b'sim2real-victim-object-' + bytes(reversed(range(64)))

_ONLINE_TIMEOUT_S = 900.0
#: A new server's DNS name can take many minutes to resolve; the session retries to this.
_SESSION_TIMEOUT_S = 900.0
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
    """An SFTP rename onto an existing name is refused (SSH_FX_FAILURE) and posix-rename is
    unsupported, both objects keep their exact bytes, and a rename onto a fresh name succeeds:
    Transfer never clobbers a destination by rename.
    """
    try:
        import paramiko
    except ImportError as exc:
        raise RequiredToolMissing(["paramiko"], "module") from exc

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
              {"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-clobber-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    key = paramiko.RSAKey.generate(2048)
    username = ctx.unique_name("sim2realclobber")
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
    transport = _connect(host, username, key, min(_SESSION_TIMEOUT_S, ctx.time_left() or _SESSION_TIMEOUT_S))
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)

        # --- full setup: two objects that exist, uploaded over the protocol under test
        sftp.putfo(io.BytesIO(_BYTES_A), "source.bin")
        sftp.putfo(io.BytesIO(_BYTES_B), "victim.bin")
        listed = sorted(sftp.listdir("."))
        assert listed == ["source.bin", "victim.bin"], (
            f"setup did not produce both objects: the home listing was {listed!r}"
        )

        # --- break exactly one thing: the destination of the rename already exists
        refused = _sftp_error(lambda: sftp.rename("source.bin", "victim.bin"),
                              "a rename onto an existing name")
        assert type(refused) is OSError, (
            f"the rename was refused with {type(refused).__name__}, expected a bare OSError "
            f"carrying SSH_FX_FAILURE (str was {str(refused)!r})"
        )
        assert refused.errno is None, (
            f"the SSH_FX_FAILURE refusal carried errno {refused.errno!r}; real AWS sends a "
            f"failure with no errno, not a POSIX code"
        )
        assert str(refused) == f"/{bucket}/{_HOME}/victim.bin", (
            f"the refusal names {str(refused)!r}, expected the destination path "
            f"{'/' + bucket + '/' + _HOME + '/victim.bin'!r}"
        )
        _assert_both_intact(s3, bucket, "after the refused plain rename")

        # --- break the same thing by the other route: the posix-rename extension exists to
        # overwrite atomically, so a server that implements it would clobber here
        unsupported = _sftp_error(lambda: sftp.posix_rename("source.bin", "victim.bin"),
                                  "a posix_rename onto an existing name")
        assert type(unsupported) is OSError, (
            f"posix_rename was refused with {type(unsupported).__name__}, expected a bare OSError "
            f"(str was {str(unsupported)!r})"
        )
        assert str(unsupported) == "Operation unsupported", (
            f"posix_rename was refused with {str(unsupported)!r}, expected 'Operation unsupported' "
            f"— AWS Transfer does not implement the posix-rename@openssh.com extension"
        )
        _assert_both_intact(s3, bucket, "after the refused posix_rename")

        # --- the positive control, in the same session: a rename onto a FRESH name succeeds
        sftp.rename("source.bin", "fresh.bin")
        listed = sorted(sftp.listdir("."))
        assert listed == ["fresh.bin", "victim.bin"], (
            f"the rename onto a fresh name left the home listing {listed!r}, expected "
            f"['fresh.bin', 'victim.bin']"
        )
        moved = s3.get_object(Bucket=bucket, Key=f"{_HOME}/fresh.bin")["Body"].read()
        assert moved == _BYTES_A, (
            f"the object at the fresh name holds {len(moved)} bytes, not the {len(_BYTES_A)} the "
            f"source held"
        )
        code = _s3_error_code(lambda: s3.head_object(Bucket=bucket, Key=f"{_HOME}/source.bin"),
                             "head of the source key after the successful rename")
        assert code == "404", (
            f"the source key survived the successful rename, answering {code!r} instead of '404'"
        )
        survivor = s3.get_object(Bucket=bucket, Key=f"{_HOME}/victim.bin")["Body"].read()
        assert survivor == _BYTES_B, (
            f"the destination object was modified after all: it holds {len(survivor)} bytes, not "
            f"the {len(_BYTES_B)} it was created with"
        )
    finally:
        transport.close()


# ===== helpers =====
def _assert_both_intact(s3, bucket: str, when: str) -> None:
    """The effect must be ABSENT: both objects still hold exactly the bytes they were given."""
    keys = _all_keys(s3, bucket, f"{_HOME}/")
    assert keys == [f"{_HOME}/source.bin", f"{_HOME}/victim.bin"], (
        f"{when} the home prefix holds {keys!r}, expected both objects untouched"
    )
    src = s3.get_object(Bucket=bucket, Key=f"{_HOME}/source.bin")["Body"].read()
    assert src == _BYTES_A, (
        f"{when} the source object holds {len(src)} bytes, not the {len(_BYTES_A)} it was given — "
        f"a refused rename must not move anything"
    )
    victim = s3.get_object(Bucket=bucket, Key=f"{_HOME}/victim.bin")["Body"].read()
    assert victim == _BYTES_B, (
        f"{when} the destination object holds {len(victim)} bytes, not the {len(_BYTES_B)} it was "
        f"given — a refused rename must not clobber the destination"
    )


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
    bucket = ctx.unique_name("sim2real-transfer-clobber-")
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
    name = ctx.unique_name("sim2real-transfer-clobber-role-")
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
