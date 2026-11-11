"""execute-query-malformed-sql-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-query-malformed-sql-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteQuery rejects a syntactically invalid SQL statement with InvalidRequestException; a
    syntactically valid statement against the same asset (positive control) succeeds."""
    sw = ctx.client("iotsitewise")
    model_id = _create_asset_model_active(ctx, sw, ctx.unique_name("sim2real-sw-model-"), properties=[])
    asset_name = ctx.unique_name("sim2real-sw-asset-")
    asset_id = _create_asset_active(ctx, sw, asset_name, model_id)

    malformed = "SELEKT * FRUM asset WHERE"
    code, message = _error(lambda: sw.execute_query(queryStatement=malformed))
    assert code == "InvalidRequestException", f"unexpected code: {code}"
    expected_message = f"Invalid SiteWiseQL Query statement: no viable alternative at input '{malformed}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: syntactically valid SQL against the same asset succeeds.
    valid_query = f"SELECT a.asset_id FROM asset a WHERE a.asset_id = '{asset_id}'"
    rows = _poll_until(
        lambda: sw.execute_query(queryStatement=valid_query)["rows"],
        lambda r: len(r) >= 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    got = rows[0]["data"][0]["scalarValue"]
    assert got == asset_id, f"expected asset_id {asset_id!r}, got {got!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a query real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this query, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_asset_model_active(ctx, sw, name, properties, hierarchies=None, timeout_s=180.0):
    kwargs = {
        "assetModelName": name,
        "assetModelProperties": properties,
        "tags": {"sim2real": "true"},
    }
    if hierarchies:
        kwargs["assetModelHierarchies"] = hierarchies
    resp = sw.create_asset_model(**kwargs)
    model_id = resp["assetModelId"]

    def _cleanup():
        try:
            sw.delete_asset_model(assetModelId=model_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    state = _poll_until(
        lambda: sw.describe_asset_model(assetModelId=model_id)["assetModelStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=3.0,
    )
    if state != "ACTIVE":
        raise AssertionError(f"asset model did not become ACTIVE (state={state})")
    return model_id


def _create_asset_active(ctx, sw, name, model_id, timeout_s=120.0):
    resp = sw.create_asset(assetName=name, assetModelId=model_id, tags={"sim2real": "true"})
    asset_id = resp["assetId"]

    def _cleanup():
        try:
            sw.delete_asset(assetId=asset_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    state = _poll_until(
        lambda: sw.describe_asset(assetId=asset_id)["assetStatus"]["state"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=3.0,
    )
    if state != "ACTIVE":
        raise AssertionError(f"asset did not become ACTIVE (state={state})")
    return asset_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
