"""form-type-delete-in-use-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "form-type-delete-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises, so a
    target accepting what AWS refuses fails as an acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


def _quiet(fn):
    """Teardown only: the check may already have removed the resource."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _word_name(ctx, prefix: str) -> str:
    suffix = "".join(ch for ch in ctx.unique_name("x") if ch.isalnum())
    return prefix + suffix


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAsset on a never-registered AssetTypeId is rejected with EntityNotFoundException and
    creates no asset, while the same PutAsset on a registered AssetType/FormType pair succeeds
    and its asset reads back until deleted: PutAsset requires the asset type to exist."""
    glue = ctx.client("glue")

    bogus_asset_type_id = _word_name(ctx, "sim2realNoSuchAssetType")
    asset_id = ctx.unique_name("sim2real-asset-badtype-")
    code, message = _error(
        lambda: glue.put_asset(
            AssetTypeId=bogus_asset_type_id,
            Identifier=asset_id,
            Name="Sim2Real asset with missing asset type",
            Forms={},
        )
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected = f'{{"Message":"Asset type {bogus_asset_type_id} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no asset was created as a side effect of the rejected PutAsset.
    absent_code, absent_message = _error(lambda: glue.get_asset(Identifier=asset_id))
    assert absent_code == "EntityNotFoundException", (
        f"expected no asset to exist after the rejected PutAsset, got code {absent_code!r}"
    )
    expected = f'{{"Message":"Asset not found: {asset_id}"}}'
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    # Positive control: with a real AssetType/FormType pair registered first, PutAsset succeeds.
    form_type_name = _word_name(ctx, "Sim2RealCtrlForm")
    form_schema = f"structure {form_type_name} {{\n    classification: String\n}}"
    form_type_id = glue.put_form_type(Name=form_type_name, Schema=form_schema)["Id"]
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_form_type(Identifier=form_type_id)))

    asset_type_name = _word_name(ctx, "sim2realCtrlAssetType")
    asset_type_id = glue.put_asset_type(
        Name=asset_type_name, Forms={form_type_name: {"FormTypeIdentifier": form_type_id}}
    )["Id"]
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_asset_type(Identifier=asset_type_id)))

    ok_asset_id = ctx.unique_name("sim2real-asset-goodtype-")
    content = json.dumps({"classification": "internal"})
    glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=ok_asset_id,
        Name="Sim2Real asset with valid asset type",
        Forms={form_type_name: {"FormTypeId": form_type_id, "Content": content}},
    )
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_asset(Identifier=ok_asset_id)))
    got_ok_asset = glue.get_asset(Identifier=ok_asset_id)
    assert got_ok_asset["AssetTypeId"] == asset_type_id, (
        f"expected the valid-AssetTypeId PutAsset to be retrievable with AssetTypeId "
        f"{asset_type_id!r}, got {got_ok_asset.get('AssetTypeId')!r}"
    )

    # Delete proves gone: the created asset is removed and an independent read 404s.
    glue.delete_asset(Identifier=ok_asset_id)
    gone_code, gone_message = _error(lambda: glue.get_asset(Identifier=ok_asset_id))
    assert gone_code == "EntityNotFoundException", (
        f"expected the deleted asset {ok_asset_id!r} to be gone, got code {gone_code!r}"
    )
    expected = f'{{"Message":"Asset not found: {ok_asset_id}"}}'
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


