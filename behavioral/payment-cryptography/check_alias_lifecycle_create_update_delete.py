"""alias-lifecycle-create-update-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "alias-lifecycle-create-update-delete"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAlias binds a name to a key, UpdateAlias re-points it to a different key, and
    DeleteAlias removes the binding so GetAlias subsequently raises ResourceNotFoundException and
    a further mutation (UpdateAlias) on the dead name is rejected the same way."""
    pc = ctx.client("payment-cryptography")
    key1 = _create_key(ctx, pc)
    key2 = _create_key(ctx, pc)
    alias_name = "alias/" + ctx.unique_name("sim2real-pc-").rstrip("-")

    created = pc.create_alias(AliasName=alias_name, KeyArn=key1["KeyArn"])["Alias"]
    ctx.on_cleanup(lambda: _safe_delete_alias(pc, alias_name))
    assert created["AliasName"] == alias_name, (
        f"expected CreateAlias to echo AliasName={alias_name!r}, got {created['AliasName']!r}"
    )
    assert created["KeyArn"] == key1["KeyArn"], (
        f"expected new alias bound to key1 {key1['KeyArn']!r}, got {created['KeyArn']!r}"
    )

    fetched = pc.get_alias(AliasName=alias_name)["Alias"]
    assert fetched["KeyArn"] == key1["KeyArn"], (
        f"expected GetAlias to read back key1 {key1['KeyArn']!r}, got {fetched['KeyArn']!r}"
    )

    updated = pc.update_alias(AliasName=alias_name, KeyArn=key2["KeyArn"])["Alias"]
    assert updated["KeyArn"] == key2["KeyArn"], (
        f"expected UpdateAlias to re-point to key2 {key2['KeyArn']!r}, got {updated['KeyArn']!r}"
    )
    fetched2 = pc.get_alias(AliasName=alias_name)["Alias"]
    assert fetched2["KeyArn"] == key2["KeyArn"], (
        f"expected GetAlias after update to read key2 {key2['KeyArn']!r}, got {fetched2['KeyArn']!r}"
    )

    pc.delete_alias(AliasName=alias_name)
    err = _client_error(lambda: pc.get_alias(AliasName=alias_name))
    _assert_not_found(err, alias_name, "GetAlias on a deleted alias")

    err2 = _client_error(lambda: pc.update_alias(AliasName=alias_name, KeyArn=key1["KeyArn"]))
    _assert_not_found(err2, alias_name, "UpdateAlias on a deleted alias")


def _assert_not_found(response: dict, resource_id: str, what: str) -> None:
    """AWS answers a missing alias with ResourceNotFoundException, an empty message and the
    missing name in ResourceId."""
    error = response.get("Error", {})
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected {what} to raise ResourceNotFoundException, got {error!r}"
    )
    assert error.get("Message", "") == "", (
        f"expected {what} to carry an empty message, got {error.get('Message')!r}"
    )
    assert response.get("ResourceId") == resource_id, (
        f"expected {what} to name ResourceId={resource_id!r}, got {response.get('ResourceId')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error response. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response
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
        Tags=[{"Key": "sim2real-check", "Value": "alias-lifecycle-create-update-delete"}],
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
