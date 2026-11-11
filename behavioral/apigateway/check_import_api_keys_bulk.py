"""import-api-keys-bulk."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "import-api-keys-bulk"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys from a CSV payload creates every row's key, and GetApiKeys lists each with
    its imported name and the enabled state its Enabled column specified (TRUE or FALSE)."""
    apigw = ctx.client("apigateway")

    name1 = ctx.unique_name("sim2real-impkey-a-")
    name2 = ctx.unique_name("sim2real-impkey-b-")
    key1 = "k" + uuid.uuid4().hex + uuid.uuid4().hex[:10]  # >20 chars, alnum
    key2 = "k" + uuid.uuid4().hex + uuid.uuid4().hex[:10]

    csv_body = (
        "name,key,Enabled\n"
        f"{name1},{key1},TRUE\n"
        f"{name2},{key2},FALSE\n"
    ).encode("utf-8")

    imported = apigw.import_api_keys(body=csv_body, format="csv", failOnWarnings=True)
    ids = imported["ids"]
    assert len(ids) == 2, f"expected 2 imported key ids, got {ids}"
    for key_id in ids:
        ctx.on_cleanup(lambda kid=key_id: apigw.delete_api_key(apiKey=kid))

    listed = _list_all_api_keys(apigw)
    by_id = {k["id"]: k for k in listed}
    assert set(ids).issubset(by_id.keys()), "all imported key ids must appear in GetApiKeys"

    imported_items = [by_id[kid] for kid in ids]
    by_name = {item["name"]: item for item in imported_items}
    assert name1 in by_name, f"expected key named {name1!r} among imported items {imported_items}"
    assert name2 in by_name, f"expected key named {name2!r} among imported items {imported_items}"

    item1 = by_name[name1]
    item2 = by_name[name2]

    assert item1["name"] == name1 and item1["enabled"] is True, (
        f"expected {name1!r} enabled=True (Enabled=TRUE row), got {item1}"
    )
    assert item2["name"] == name2 and item2["enabled"] is False, (
        f"expected {name2!r} enabled=False (Enabled=FALSE row), got {item2}"
    )


def _list_all_api_keys(apigw):
    items = []
    position = None
    for _ in range(10):
        kwargs = {"limit": 500}
        if position:
            kwargs["position"] = position
        page = apigw.get_api_keys(**kwargs)
        items.extend(page.get("items", []))
        position = page.get("position")
        if not position:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
