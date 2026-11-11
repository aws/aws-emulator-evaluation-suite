"""import-api-keys-bulk-creates-from-payload."""
from __future__ import annotations

import csv
import io
import uuid

from behavioral_harness import tags

CHECK = "import-api-keys-bulk-creates-from-payload"
GROUP = 'api-keys'
SERVICES = ['apigateway']


def _api_keys_csv_body(rows):
    """CSV body for ImportApiKeys format='csv' (Key values must be 20-128 chars)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "key", "description", "enabled"])
    for row in rows:
        writer.writerow(
            [
                row.get("name", ""),
                row.get("key", ""),
                row.get("description", ""),
                row.get("enabled", "TRUE"),
            ]
        )
    return buf.getvalue().encode("utf-8")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys creates one ApiKey per CSV row in a single call; each key is retrievable with
    the name, enabled flag and value from its row."""
    ag = ctx.client("apigateway")
    unique = uuid.uuid4().hex
    row_1 = {
        "name": ctx.unique_name("sim2real-behav-bulkkey1-"),
        "key": f"sim2realBulk1{unique}"[:40],
        "description": "bulk import row 1",
        "enabled": "TRUE",
    }
    row_2 = {
        "name": ctx.unique_name("sim2real-behav-bulkkey2-"),
        "key": f"sim2realBulk2{unique}"[:40],
        "description": "bulk import row 2",
        "enabled": "FALSE",
    }
    body = _api_keys_csv_body([row_1, row_2])

    result = ag.import_api_keys(body=body, format="csv")
    ids = result.get("ids", [])
    assert len(ids) == 2, f"expected ImportApiKeys to create exactly 2 keys from 2 CSV rows, got ids={ids!r}"
    for key_id in ids:
        ctx.on_cleanup(lambda kid=key_id: ag.delete_api_key(apiKey=kid))
        ag.tag_resource(
            resourceArn=f"arn:aws:apigateway:{ctx.region}::/apikeys/{key_id}",
            tags={"sim2real": "true"},
        )

    fetched = {kid: ag.get_api_key(apiKey=kid, includeValue=True) for kid in ids}
    by_name = {k["name"]: k for k in fetched.values()}

    assert row_1["name"] in by_name, f"expected key {row_1['name']!r} to be retrievable after bulk import"
    assert row_2["name"] in by_name, f"expected key {row_2['name']!r} to be retrievable after bulk import"
    assert by_name[row_1["name"]]["enabled"] is True, "expected row 1's enabled=TRUE to round-trip"
    assert by_name[row_2["name"]]["enabled"] is False, "expected row 2's enabled=FALSE to round-trip"
    assert by_name[row_1["name"]]["value"] == row_1["key"], "expected the imported key VALUE to match the CSV payload"
    assert by_name[row_2["name"]]["value"] == row_2["key"], "expected the imported key VALUE to match the CSV payload"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
