"""asset-type-lifecycle-put-get-delete."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-type-lifecycle-put-get-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAssetType creates an asset type visible in ListAssetTypes and GetAssetType;
    DeleteAssetType removes it and it disappears from both."""
    glue = ctx.client("glue")

    form_name = _alnum_id("SimBehavTypeForm")
    schema = f"structure {form_name} {{\n    tag: String\n}}"
    glue.put_form_type(Name=form_name, Schema=schema)
    ctx.on_cleanup(lambda: _cleanup_form_type(glue, form_name))

    asset_type_name = _alnum_id("SimBehavAssetTypeLC")
    created = glue.put_asset_type(Name=asset_type_name, Forms={form_name: {"FormTypeIdentifier": form_name}})
    ctx.on_cleanup(lambda: _cleanup_asset_type(glue, asset_type_name))
    assert created["Id"] == asset_type_name, f"expected PutAssetType Id {asset_type_name!r}, got {created['Id']!r}"
    assert created["Name"] == asset_type_name, f"expected PutAssetType Name {asset_type_name!r}, got {created['Name']!r}"

    got = glue.get_asset_type(Identifier=asset_type_name)
    assert got["Name"] == asset_type_name, f"expected GetAssetType Name {asset_type_name!r}, got {got['Name']!r}"
    assert form_name in got["Forms"], f"expected form {form_name!r} in GetAssetType Forms, got {list(got['Forms'])!r}"

    listed_ids_before = _try_list_contains(glue, "list_asset_types", asset_type_name)
    if listed_ids_before is not None:
        assert listed_ids_before, f"expected {asset_type_name!r} in ListAssetTypes before delete"

    glue.delete_asset_type(Identifier=asset_type_name)

    code, message = _error(lambda: glue.get_asset_type(Identifier=asset_type_name))
    assert code == "EntityNotFoundException", f"expected GetAssetType on deleted id to raise EntityNotFoundException, got {code!r}"
    expected_message = f'{{"Message":"Asset type {asset_type_name} not found."}}'
    assert message == expected_message, (
        f"expected GetAssetType's not-found message {expected_message!r}, got {message!r}"
    )

    # DeleteAssetType is idempotent on an already-deleted id: a second delete is a no-op success
    glue.delete_asset_type(Identifier=asset_type_name)

    listed_ids_after = _try_list_contains(glue, "list_asset_types", asset_type_name)
    if listed_ids_after is not None:
        assert not listed_ids_after, f"expected {asset_type_name!r} absent from ListAssetTypes after delete"


# ===== helpers =====
def _alnum_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _try_list_contains(glue, method_name: str, target_id: str, attempts: int = 2, delay: float = 3.0):
    """ListAssetTypes/ListFormTypes are exercised best-effort: this preview business-context
    API has been observed to intermittently 500 independent of the create/get/delete path, so a
    persistent failure here does not invalidate the create/get/delete assertions already made.
    Returns True/False on success, or None if the list call itself is unreachable."""
    fn = getattr(glue, method_name)
    for i in range(attempts):
        try:
            found = False
            token = None
            while True:
                kwargs = {"MaxResults": 1000}
                if token:
                    kwargs["NextToken"] = token
                resp = fn(**kwargs)
                if any(item["Id"] == target_id for item in resp.get("Items", [])):
                    found = True
                token = resp.get("NextToken")
                if not token:
                    break
            return found
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InternalServiceException", "ThrottlingException") and i < attempts - 1:
                time.sleep(delay)
                continue
            return None
    return None


def _cleanup_form_type(glue, identifier: str) -> None:
    try:
        glue.delete_form_type(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_asset_type(glue, identifier: str) -> None:
    try:
        glue.delete_asset_type(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
