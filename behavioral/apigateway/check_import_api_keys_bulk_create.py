"""import-api-keys-bulk-create."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "import-api-keys-bulk-create"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys bulk-creates API keys from a CSV payload, all visible via GetApiKeys."""
    apigw = ctx.client("apigateway")
    name1 = ctx.unique_name("sim2real-key1-")
    name2 = ctx.unique_name("sim2real-key2-")
    key1 = _random_key_value()
    key2 = _random_key_value()
    csv_body = (
        "name,key,description\n"
        f"{name1},{key1},sim2real imported key one\n"
        f"{name2},{key2},sim2real imported key two\n"
    )

    imported = apigw.import_api_keys(
        body=csv_body.encode("utf-8"), format="csv", failOnWarnings=True
    )
    ids = imported["ids"]
    assert len(ids) == 2, imported
    assert imported.get("warnings", []) == [], imported["warnings"]

    def _cleanup():
        for key_id in ids:
            _delete_key_if_present(apigw, key_id)

    ctx.on_cleanup(_cleanup)

    for key_id in ids:
        apigw.tag_resource(
            resourceArn=f"arn:aws:apigateway:{ctx.region}::/apikeys/{key_id}",
            tags={"sim2real": "check_import_api_keys_bulk_create"},
        )

    by_name = {}
    for key_id in ids:
        key = apigw.get_api_key(apiKey=key_id, includeValue=True)
        by_name[key["name"]] = key

    assert set(by_name.keys()) == {name1, name2}, by_name.keys()
    assert by_name[name1]["value"] == key1, (by_name[name1]["value"], key1)
    assert by_name[name1]["description"] == "sim2real imported key one", by_name[name1]["description"]
    assert by_name[name2]["value"] == key2, (by_name[name2]["value"], key2)
    assert by_name[name2]["description"] == "sim2real imported key two", by_name[name2]["description"]

    listed = apigw.get_api_keys(nameQuery=name1)["items"]
    assert any(k["id"] == by_name[name1]["id"] for k in listed), listed

    # the delete this check already performs in cleanup is a free negative: prove it
    # actually removes the resource rather than merely returning 200.
    dead_id = by_name[name1]["id"]
    apigw.delete_api_key(apiKey=dead_id)
    ids.remove(dead_id)

    from botocore.exceptions import ClientError

    try:
        apigw.get_api_key(apiKey=dead_id)
        raise AssertionError(f"expected deleted key {dead_id} to be NotFoundException, got a response")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "NotFoundException", err.response["Error"]
        assert err.response["Error"].get("Message") == "Invalid API Key identifier specified", err.response["Error"]

    still_listed = apigw.get_api_keys(nameQuery=name1)["items"]
    assert not any(k["id"] == dead_id for k in still_listed), still_listed

    try:
        apigw.delete_api_key(apiKey=dead_id)
        raise AssertionError(f"expected a second delete of {dead_id} to be NotFoundException, got success")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "NotFoundException", err.response["Error"]
        assert err.response["Error"].get("Message") == "Invalid API Key identifier specified", err.response["Error"]


def _random_key_value() -> str:
    raw = (uuid.uuid4().hex + uuid.uuid4().hex)[:30]
    return raw


def _delete_key_if_present(apigw, key_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        apigw.delete_api_key(apiKey=key_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
