"""create-alias-duplicate-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-alias-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias on an existing name for a different key gets ConflictException with the exact message
    and the alias keeps its key; a fresh alias for the second key succeeds, and after the original alias
    is deleted the same name binds to the second key."""
    pc = ctx.client("payment-cryptography")
    key1 = _create_key(ctx, pc)
    key2 = _create_key(ctx, pc)
    alias_name = "alias/" + ctx.unique_name("sim2real-pc-dup-").rstrip("-")
    ctx.on_cleanup(lambda: _safe_delete_alias(pc, alias_name))

    pc.create_alias(AliasName=alias_name, KeyArn=key1["KeyArn"])

    error = _client_error(
        lambda: pc.create_alias(AliasName=alias_name, KeyArn=key2["KeyArn"])
    )
    assert error.get("Code") == "ConflictException", f"expected ConflictException, got {error!r}"
    expected_message = f"Alias {alias_name} already exists."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    unchanged = pc.get_alias(AliasName=alias_name)["Alias"]
    assert unchanged["KeyArn"] == key1["KeyArn"], (
        f"alias must still point at key1 {key1['KeyArn']!r} after the rejected rebind, "
        f"got {unchanged['KeyArn']!r}"
    )

    # positive control: a fresh, unique alias name for the second key succeeds, so the
    # ConflictException above cannot be a blanket denial of CreateAlias for key2
    other_alias_name = "alias/" + ctx.unique_name("sim2real-pc-dup2-").rstrip("-")
    ctx.on_cleanup(lambda: _safe_delete_alias(pc, other_alias_name))
    created2 = pc.create_alias(AliasName=other_alias_name, KeyArn=key2["KeyArn"])["Alias"]
    assert created2["KeyArn"] == key2["KeyArn"], (
        f"fresh alias must bind to key2 {key2['KeyArn']!r}, got {created2['KeyArn']!r}"
    )

    # restore: free the contested name and retry the identical call — it must now succeed,
    # proving the earlier rejection was the name collision and not a hidden general refusal
    pc.delete_alias(AliasName=alias_name)
    restored = pc.create_alias(AliasName=alias_name, KeyArn=key2["KeyArn"])["Alias"]
    assert restored["KeyArn"] == key2["KeyArn"], (
        f"identical call must succeed once the name is freed, got {restored['KeyArn']!r}"
    )
    reread = pc.get_alias(AliasName=alias_name)["Alias"]
    assert reread["KeyArn"] == key2["KeyArn"], (
        f"independent read must reflect the restored bind to key2 {key2['KeyArn']!r}, "
        f"got {reread['KeyArn']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_key(ctx, pc):
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    key = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Key"]
    arn = key["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))
    return key


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_alias(pc, alias_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_alias(AliasName=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
