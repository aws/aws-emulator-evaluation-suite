"""asset-lifecycle-put-get-delete-404."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "asset-lifecycle-put-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAsset creates an asset conforming to an asset type's forms, GetAsset returns it,
    DeleteAsset removes it and a subsequent GetAsset raises EntityNotFoundException."""
    glue = ctx.client("glue")

    form_type_id, form_type_name = _create_form_type(ctx, glue)
    asset_type_id = _create_asset_type(ctx, glue, form_type_name, form_type_id)

    asset_id = ctx.unique_name("sim2real-asset-")
    created = glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=asset_id,
        Name="behavioral-fidelity-asset",
        Description="created by a behavioral fidelity check",
        Forms={form_type_name: {"FormTypeId": form_type_id, "Content": '{"note": "hello"}'}},
    )
    assert created["Id"] == asset_id, f"expected Id {asset_id!r}, got {created['Id']!r}"
    assert created["Name"] == "behavioral-fidelity-asset", (
        f"expected Name 'behavioral-fidelity-asset', got {created['Name']!r}"
    )

    ctx.on_cleanup(lambda: _delete_tolerating(lambda: glue.delete_asset(Identifier=asset_id)))

    got = glue.get_asset(Identifier=asset_id)
    assert got["Id"] == asset_id, f"GetAsset returned Id {got['Id']!r}, expected {asset_id!r}"
    assert got["AssetTypeId"] == asset_type_id, (
        f"GetAsset returned AssetTypeId {got['AssetTypeId']!r}, expected {asset_type_id!r}"
    )
    got_content = json.loads(got["Forms"][form_type_name]["Content"])
    assert got_content == {"note": "hello"}, (
        f"GetAsset form content {got_content!r} did not round-trip the PutAsset content"
    )

    glue.delete_asset(Identifier=asset_id)

    expected_message = f'{{"Message":"Asset not found: {asset_id}"}}'
    code, message = _error(lambda: glue.get_asset(Identifier=asset_id))
    assert code == "EntityNotFoundException", (
        f"GetAsset on a deleted asset raised {code!r}, expected EntityNotFoundException"
    )
    assert message == expected_message, (
        f"GetAsset on a deleted asset: expected message {expected_message!r}, got {message!r}"
    )

    # real AWS treats DeleteAsset as idempotent: a second delete is a no-op success
    glue.delete_asset(Identifier=asset_id)
    code, message = _error(lambda: glue.get_asset(Identifier=asset_id))
    assert code == "EntityNotFoundException", (
        f"a double-deleted asset must not have been resurrected, but GetAsset raised {code!r}"
    )
    assert message == expected_message, (
        f"GetAsset on a double-deleted asset: expected message {expected_message!r}, got {message!r}"
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


def _create_asset_type(ctx, glue, form_key_name, form_type_id):
    name = _pascal_name(ctx, "sim2real-assettype-")
    resp = glue.put_asset_type(
        Name=name, Forms={form_key_name: {"FormTypeIdentifier": form_type_id}}
    )
    asset_type_id = resp["Id"]

    ctx.on_cleanup(lambda: _delete_tolerating(lambda: glue.delete_asset_type(Identifier=asset_type_id)))
    return asset_type_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
