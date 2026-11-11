"""get-asset-nonexistent-identifier-rejected."""
from __future__ import annotations

import json
import uuid

import botocore

from behavioral_harness import tags

CHECK = "get-asset-nonexistent-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAsset on an identifier that was never put raises EntityNotFoundException with the exact
    message, while GetAsset on a created asset returns its Name.
    """
    glue = ctx.client("glue")

    suffix = uuid.uuid4().hex[:10]
    form_type_name = f"Sim2RealForm{suffix}"
    form_type = glue.put_form_type(
        Name=form_type_name,
        Schema=f"structure {form_type_name} {{ k: String }}",
    )
    form_type_id = form_type["Id"]
    ctx.on_cleanup(lambda: glue.delete_form_type(Identifier=form_type_id))

    asset_type = glue.put_asset_type(
        Name=f"Sim2RealAssetType{suffix}",
        Forms={"MainForm": {"FormTypeIdentifier": form_type_id}},
    )
    asset_type_id = asset_type["Id"]
    ctx.on_cleanup(lambda: glue.delete_asset_type(Identifier=asset_type_id))

    # Positive control: a valid AssetTypeId succeeds and is retrievable.
    good_asset_id = ctx.unique_name("sim2real-asset-good-")
    glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=good_asset_id,
        Name="good asset",
        Forms={"MainForm": {"FormTypeId": form_type_id, "Content": json.dumps({"k": "v"})}},
    )
    ctx.on_cleanup(lambda: glue.delete_asset(Identifier=good_asset_id))
    good_name = glue.get_asset(Identifier=good_asset_id)["Name"]
    assert good_name == "good asset", f"expected positive control Name='good asset', got {good_name!r}"

    # Negative: an identifier that was never written is rejected outright by reads -- there is
    # no ambient/implicit asset record for it. (DeleteAsset on a never-created identifier is
    # treated as an idempotent no-op by real AWS rather than raising, so it isn't used as the
    # negative boundary here.)
    bad_asset_id = ctx.unique_name("sim2real-asset-never-created-")
    # AWS wraps this refusal's text in a JSON object inside the Message field.
    expected_message = '{"Message":"Asset not found: ' + bad_asset_id + '"}'
    get_code, get_message = _error_code(lambda: glue.get_asset(Identifier=bad_asset_id))
    assert get_code == "EntityNotFoundException", (
        f"expected GetAsset on a never-created Identifier to raise EntityNotFoundException, got {get_code!r}"
    )
    assert get_message == expected_message, (
        f"expected GetAsset message {expected_message!r}, got {get_message!r}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
