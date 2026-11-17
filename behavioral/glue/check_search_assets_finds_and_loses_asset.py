"""search-assets-finds-and-loses-asset."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "search-assets-finds-and-loses-asset"
GROUP = "state-machine"
SERVICES = ["glue"]


def _alnum_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _search_ids(glue, search_text: str) -> set[str]:
    found = set()
    for page in glue.get_paginator("search_assets").paginate(SearchText=search_text):
        found.update(item["Id"] for item in page["Items"])
    return found


def _poll_until(observe, predicate, *, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = observe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = observe()
    return value


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchAssets finds a created asset by a token unique to its name, and converges
    to no longer finding it once the asset is deleted.
    """
    glue = ctx.client("glue")

    form_name = _alnum_id("Sim2RealBehavSearchForm")
    glue.put_form_type(Name=form_name, Schema=f"structure {form_name} {{\n    kind: String\n}}")
    ctx.on_cleanup(lambda: glue.delete_form_type(Identifier=form_name))

    asset_type_name = _alnum_id("Sim2RealBehavSearchType")
    glue.put_asset_type(Name=asset_type_name, Forms={form_name: {"FormTypeIdentifier": form_name}})
    ctx.on_cleanup(lambda: glue.delete_asset_type(Identifier=asset_type_name))

    search_token = _alnum_id("Sim2RealSearchToken")
    asset_id = ctx.unique_name("sim2real-behav-search-asset-")
    glue.put_asset(
        AssetTypeId=asset_type_name,
        Identifier=asset_id,
        Name=f"searchable asset {search_token}",
        Description="a check-owned asset searched for by its unique token",
        Forms={form_name: {"FormTypeId": form_name, "Content": json.dumps({"kind": "table"})}},
    )
    ctx.on_cleanup(lambda: glue.delete_asset(Identifier=asset_id))

    found_ids = _poll_until(
        lambda: _search_ids(glue, search_token), lambda ids: asset_id in ids
    )
    assert asset_id in found_ids, (
        f"SearchAssets never found the asset by its unique token {search_token!r}, "
        f"last saw {sorted(found_ids)!r}"
    )

    glue.delete_asset(Identifier=asset_id)

    found_after_delete = _poll_until(
        lambda: _search_ids(glue, search_token), lambda ids: asset_id not in ids
    )
    assert asset_id not in found_after_delete, (
        f"SearchAssets still finds a deleted asset {asset_id!r} after waiting for the index to catch up"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
