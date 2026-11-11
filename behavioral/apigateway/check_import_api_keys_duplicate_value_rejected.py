"""import-api-keys-duplicate-value-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-api-keys-duplicate-value-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys collapses two CSV rows sharing one key value into a single ApiKey that keeps
    the LAST row's attributes, verified via independent GetApiKey and GetApiKeys reads.
    Uniqueness is enforced only within the payload, not against existing ApiKeys."""
    apigw = ctx.client("apigateway")

    dup_value = uuid.uuid4().hex + uuid.uuid4().hex[:10]
    name_first = ctx.unique_name("sim2real-behav-dup-first-")
    name_second = ctx.unique_name("sim2real-behav-dup-second-")
    csv_body = (
        f"name,key\n{name_first},{dup_value}\n{name_second},{dup_value}\n"
    ).encode("utf-8")

    # Even with failOnWarnings=True AWS returns 201 and silently drops the earlier duplicate row;
    # "warnings" stays empty.
    result = apigw.import_api_keys(body=csv_body, format="csv", failOnWarnings=True)
    imported_ids = result.get("ids") or []
    for key_id in imported_ids:
        ctx.on_cleanup(lambda kid=key_id: _safe(lambda: apigw.delete_api_key(apiKey=kid)))
        apigw.tag_resource(
            resourceArn=f"arn:aws:apigateway:{ctx.region}::/apikeys/{key_id}",
            tags={"sim2real": "true"},
        )

    assert result.get("warnings") == [], (
        f"expected the dropped duplicate row to be silent (no warnings), got {result!r}"
    )
    assert len(imported_ids) == 1, (
        f"expected the two duplicate-value rows to collapse to exactly one ApiKey, got {result!r}"
    )

    surviving = apigw.get_api_key(apiKey=imported_ids[0], includeValue=True)
    assert surviving["value"] == dup_value, (
        f"expected the surviving key to hold the submitted value, got {surviving!r}"
    )
    assert surviving["name"] == name_second, (
        f"expected the *last* duplicate row ({name_second!r}) to win, got name={surviving['name']!r}"
    )

    all_keys = apigw.get_api_keys(limit=500)["items"]
    names_present = {k["name"] for k in all_keys}
    assert name_second in names_present, "the surviving (last) row should be visible via GetApiKeys"
    assert name_first not in names_present, "the dropped (first) row must not appear via GetApiKeys"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
