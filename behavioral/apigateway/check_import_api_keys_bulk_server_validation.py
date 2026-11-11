"""import-api-keys-bulk-server-validation."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "import-api-keys-bulk-server-validation"
GROUP = "server-side"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys validates each CSV record server-side: a batch with one valid record and one
    structurally-invalid record (key too short) imports the valid record and reports a warning
    for the invalid one, rather than an opaque all-or-nothing failure."""
    apigw = ctx.client("apigateway")

    valid_name = ctx.unique_name("sim2real-import-key-")
    valid_key = ("v" + uuid.uuid4().hex + uuid.uuid4().hex)[:40]  # within the 20-128 char range
    invalid_name = ctx.unique_name("sim2real-import-bad-")
    invalid_key = "tooshort1234"  # under the 20-char minimum -> structurally invalid record

    csv_body = f"Name,Key\n{valid_name},{valid_key}\n{invalid_name},{invalid_key}\n"

    resp = apigw.import_api_keys(body=csv_body.encode("utf-8"), format="csv", failOnWarnings=False)

    ids = resp.get("ids", [])
    assert len(ids) == 1, f"expected exactly one successfully-imported key, got ids={ids}"
    for key_id in ids:
        ctx.on_cleanup(lambda k=key_id: apigw.delete_api_key(apiKey=k))

    warnings = resp.get("warnings") or []
    assert len(warnings) == 1, f"expected exactly one warning for the one invalid record, got {warnings}"
    assert "20 characters" in warnings[0], (
        f"expected the warning to describe the key-length violation, got {warnings[0]!r}"
    )

    created = apigw.get_api_key(apiKey=ids[0])
    assert created["name"] == valid_name, f"expected imported key name {valid_name!r}, got {created!r}"

    # the invalid record must genuinely have been skipped, not silently imported
    listed = apigw.get_api_keys(nameQuery=invalid_name)["items"]
    assert listed == [], f"the structurally-invalid record should not have been imported, got {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
