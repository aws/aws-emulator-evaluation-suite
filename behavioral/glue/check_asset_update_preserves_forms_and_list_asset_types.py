"""asset-update-preserves-forms-and-list-asset-types."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-update-preserves-forms-and-list-asset-types"
GROUP = "state-machine"
SERVICES = ["glue"]


def _alnum_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAsset replaces an asset's Name and Description without touching its Forms,
    ListAssetTypes surfaces a created asset type, and UpdateAsset rejects an unknown id.
    """
    glue = ctx.client("glue")

    form_name = _alnum_id("Sim2RealBehavAssetForm")
    glue.put_form_type(Name=form_name, Schema=f"structure {form_name} {{\n    kind: String\n}}")
    ctx.on_cleanup(_teardown(lambda: glue.delete_form_type(Identifier=form_name), "EntityNotFoundException"))

    asset_type_name = _alnum_id("Sim2RealBehavAssetType")
    glue.put_asset_type(Name=asset_type_name, Forms={form_name: {"FormTypeIdentifier": form_name}})
    ctx.on_cleanup(_teardown(lambda: glue.delete_asset_type(Identifier=asset_type_name), "EntityNotFoundException"))

    asset_id = ctx.unique_name("sim2real-behav-asset-upd-")
    form_content = json.dumps({"kind": "table"})
    glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name="original name",
        Description="original description",
        Forms={form_name: {"FormTypeId": form_name, "Content": form_content}},
    )
    ctx.on_cleanup(_teardown(lambda: glue.delete_asset(Identifier=asset_id), "EntityNotFoundException"))

    glue.update_asset(Identifier=asset_id, Name="updated name", Description="updated description")

    updated = glue.get_asset(Identifier=asset_id)
    assert updated["Name"] == "updated name", f"UpdateAsset did not replace Name: {updated['Name']!r}"
    assert updated["Description"] == "updated description", (
        f"UpdateAsset did not replace Description: {updated['Description']!r}"
    )
    updated_content = json.loads(updated["Forms"][form_name]["Content"])
    assert updated_content == {"kind": "table"}, (
        f"UpdateAsset (which takes no Forms argument) changed the asset's form content: {updated_content!r}"
    )

    # negative: updating an asset that was never created is rejected
    missing_asset_id = ctx.unique_name("sim2real-behav-asset-missing-")
    code, msg = _error(lambda: glue.update_asset(Identifier=missing_asset_id, Name="x"))
    assert code == "EntityNotFoundException", f"UpdateAsset on an unknown asset gave {code!r}"
    assert msg == f'{{"Message":"Asset not found: {missing_asset_id}"}}', f"unexpected message: {msg!r}"

    # ListAssetTypes surfaces the asset type this check created
    names = set()
    for page in glue.get_paginator("list_asset_types").paginate():
        names.update(item["Name"] for item in page["Items"])
    assert asset_type_name in names, f"ListAssetTypes did not include {asset_type_name!r}"

    # delete proves gone: the asset no longer answers Get or Update
    glue.delete_asset(Identifier=asset_id)
    code_get, msg_get = _error(lambda: glue.get_asset(Identifier=asset_id))
    assert code_get == "EntityNotFoundException", f"reading a deleted asset gave {code_get!r}"
    assert msg_get == f'{{"Message":"Asset not found: {asset_id}"}}', f"unexpected message: {msg_get!r}"
    code_update, msg_update = _error(lambda: glue.update_asset(Identifier=asset_id, Name="y"))
    assert code_update == "EntityNotFoundException", f"updating a deleted asset gave {code_update!r}"
    assert msg_update == f'{{"Message":"Asset not found: {asset_id}"}}', f"unexpected message: {msg_update!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
