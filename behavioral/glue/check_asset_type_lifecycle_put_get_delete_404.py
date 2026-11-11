"""asset-type-lifecycle-put-get-delete-404."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "asset-type-lifecycle-put-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAssetType creates an asset type definition referencing a form type, GetAssetType
    returns it, DeleteAssetType removes it and a subsequent GetAssetType raises
    EntityNotFoundException."""
    glue = ctx.client("glue")

    form_type_id, form_type_name = _create_form_type(ctx, glue)

    asset_type_name = _pascal_name(ctx, "sim2real-assettype-")
    created = glue.put_asset_type(
        Name=asset_type_name, Forms={form_type_name: {"FormTypeIdentifier": form_type_id}}
    )
    asset_type_id = created["Id"]
    assert created["Name"] == asset_type_name, (
        f"PutAssetType response Name mismatch: expected {asset_type_name!r}, got {created['Name']!r}"
    )

    ctx.on_cleanup(lambda: _delete_tolerating(lambda: glue.delete_asset_type(Identifier=asset_type_id)))

    got = _poll_get_asset_type(glue, asset_type_id)
    # GetAssetType returns the Id qualified as "glue_<account>::<name>" while PutAssetType's
    # response Id is the bare name — both resolve the same resource.
    assert got["Id"] == asset_type_id or got["Id"].endswith(f"::{asset_type_id}"), (
        f"GetAssetType Id mismatch: expected {asset_type_id!r} (bare or ::-qualified), got {got['Id']!r}"
    )
    assert got["Name"] == asset_type_name, (
        f"GetAssetType Name mismatch: expected {asset_type_name!r}, got {got['Name']!r}"
    )
    assert got["Forms"][form_type_name]["FormTypeIdentifier"].lower() == form_type_id.lower(), (
        f"GetAssetType Forms[{form_type_name!r}].FormTypeIdentifier mismatch: "
        f"expected {form_type_id!r} (case-insensitive), got {got['Forms'][form_type_name]['FormTypeIdentifier']!r}"
    )

    glue.delete_asset_type(Identifier=asset_type_id)

    code, message = _error(lambda: glue.get_asset_type(Identifier=asset_type_id))
    assert code == "EntityNotFoundException", (
        f"GetAssetType after DeleteAssetType: expected EntityNotFoundException, got {code!r}"
    )
    expected_message = f'{{"Message":"Asset type {asset_type_id} not found."}}'
    assert message == expected_message, (
        f"GetAssetType after DeleteAssetType: expected message {expected_message!r}, got {message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_tolerating(fn, codes=("EntityNotFoundException",)) -> None:
    """Teardown delete that tolerates the resource already being gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in codes:
            raise


def _pascal_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    cleaned = "".join(ch for ch in raw if ch.isalnum())
    return "Sim" + cleaned


def _poll_get_asset_type(glue, asset_type_id, timeout_s=30.0):
    import time

    def _matches(got):
        gid = got.get("Id", "")
        return gid == asset_type_id or gid.endswith(f"::{asset_type_id}")

    deadline = time.monotonic() + timeout_s
    got = glue.get_asset_type(Identifier=asset_type_id)
    while not _matches(got) and time.monotonic() < deadline:
        time.sleep(2)
        got = glue.get_asset_type(Identifier=asset_type_id)
    return got


def _create_form_type(ctx, glue):
    name = _pascal_name(ctx, "sim2real-formtype-")
    schema = f"structure {name} {{\n    note: String\n}}"
    resp = glue.put_form_type(Name=name, Schema=schema)
    form_type_id = resp["Id"]

    ctx.on_cleanup(
        lambda: _delete_tolerating(
            lambda: glue.delete_form_type(Identifier=form_type_id),
            ("EntityNotFoundException", "ConflictException"),
        )
    )
    return form_type_id, name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
