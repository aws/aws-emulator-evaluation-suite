"""duplicate-ssh-public-key-rejected."""
from __future__ import annotations

import json

CHECK = "duplicate-ssh-public-key-rejected"
GROUP = "representation"
SERVICES = ["transfer"]

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

try:
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.serialization import Encoding as _Encoding, PublicFormat as _PublicFormat

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportSshPublicKey rejects re-importing an identical key body for the same
    user with ResourceExistsException, the key is not duplicated, and importing a
    genuinely different key for the same user still succeeds (positive control)."""
    if not _CRYPTO_AVAILABLE:
        raise RequiredToolMissing(["cryptography"], "module")

    transfer = ctx.client("transfer")
    iam = ctx.client("iam")

    role_arn = _create_transfer_role(ctx, iam)
    server_id = transfer.create_server(Protocols=["SFTP"], Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    user_name = ctx.unique_name("sim2realuser").replace("-", "")[:32]
    _retry_role_propagation(
        lambda: transfer.create_user(
            ServerId=server_id, UserName=user_name, Role=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    key1 = _generate_public_key()
    key1_id = transfer.import_ssh_public_key(
        ServerId=server_id, SshPublicKeyBody=key1, UserName=user_name
    )["SshPublicKeyId"]

    code, message = _error(
        lambda: transfer.import_ssh_public_key(
            ServerId=server_id, SshPublicKeyBody=key1, UserName=user_name
        )
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code!r}"
    assert message == "Public key already exists", f"unexpected duplicate-key message: {message!r}"

    after_duplicate = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]["SshPublicKeys"]
    assert len(after_duplicate) == 1, "a rejected duplicate import must not add a second key"
    assert after_duplicate[0]["SshPublicKeyId"] == key1_id, (
        f"the surviving key after a rejected duplicate must be the original "
        f"{key1_id!r}, got {after_duplicate[0]['SshPublicKeyId']!r}"
    )

    # Positive control: a genuinely different key for the same user is accepted.
    key2 = _generate_public_key()
    key2_id = transfer.import_ssh_public_key(
        ServerId=server_id, SshPublicKeyBody=key2, UserName=user_name
    )["SshPublicKeyId"]
    after_second = transfer.describe_user(ServerId=server_id, UserName=user_name)["User"]["SshPublicKeys"]
    assert len(after_second) == 2, "a distinct key import should succeed and add a second key"
    assert key2_id != key1_id, "a genuinely distinct key must be assigned a distinct SshPublicKeyId"
    ids_after_second = {k["SshPublicKeyId"] for k in after_second}
    assert ids_after_second == {key1_id, key2_id}, (
        f"expected exactly the original and new key ids {{{key1_id!r}, {key2_id!r}}}, "
        f"got {ids_after_second!r}"
    )


def _retry_role_propagation(fn, attempts: int = 8, delay_s: float = 3.0):
    """A freshly created IAM role's trust policy is not always visible to Transfer
    immediately; retry the eventually-consistent AccessDenied/InvalidRequestException
    window rather than treating it as a real rejection."""
    import time as _time

    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidRequestException", "AccessDenied", "AccessDeniedException"):
                last_exc = exc
                _time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _generate_public_key():
    private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key().public_bytes(
        encoding=_Encoding.OpenSSH, format=_PublicFormat.OpenSSH
    ).decode()


def _create_transfer_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceExistsException, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
