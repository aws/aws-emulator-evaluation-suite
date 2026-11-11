"""list-functions-filters-by-stage."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-functions-filters-by-stage"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_FUNCTION_CODE = b"function handler(event) { return event.request; }"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctions lists a new function under Stage DEVELOPMENT and not under LIVE; after
    PublishFunction it lists the function under LIVE and still under DEVELOPMENT."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-fn-")

    created = cf.create_function(
        Name=name,
        FunctionConfig={"Comment": "stage-filter-check", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
    )
    ctx.on_cleanup(lambda: _delete_function(ctx, name))
    created_stage = created["FunctionSummary"]["FunctionMetadata"]["Stage"]
    assert created_stage == "DEVELOPMENT", (
        f"a freshly created function must start in DEVELOPMENT, got {created_stage!r}"
    )

    dev_names = _list_stage_names(ctx, "DEVELOPMENT")
    assert name in dev_names, (
        f"ListFunctions(Stage=DEVELOPMENT) must include the new function {name!r}, got {dev_names!r}"
    )
    live_names = _list_stage_names(ctx, "LIVE")
    assert name not in live_names, (
        f"ListFunctions(Stage=LIVE) must not include an unpublished function {name!r}, got {live_names!r}"
    )

    etag = cf.describe_function(Name=name)["ETag"]
    cf.publish_function(Name=name, IfMatch=etag)

    def _is_live() -> bool:
        return (
            cf.describe_function(Name=name, Stage="LIVE")["FunctionSummary"]["FunctionMetadata"][
                "Stage"
            ]
            == "LIVE"
        )

    assert _poll_until(_is_live, timeout_s=30.0, interval_s=2.0), "function never reached LIVE"

    live_names_after = _list_stage_names(ctx, "LIVE")
    assert name in live_names_after, (
        f"ListFunctions(Stage=LIVE) must include the published function {name!r}, got {live_names_after!r}"
    )
    dev_names_after = _list_stage_names(ctx, "DEVELOPMENT")
    assert name in dev_names_after, (
        f"publishing must not retire the DEVELOPMENT version: ListFunctions(Stage=DEVELOPMENT) "
        f"must still include {name!r} after publish, got {dev_names_after!r}"
    )


def _list_stage_names(ctx, stage: str) -> set[str]:
    cf = ctx.client("cloudfront")
    names: set[str] = set()
    marker = ""
    while True:
        kwargs = {"Stage": stage}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_functions(**kwargs)
        flist = resp.get("FunctionList", {})
        for item in flist.get("Items", []):
            names.add(item["Name"])
        marker = flist.get("NextMarker", "")
        if not marker:
            break
    return names


def _delete_function(ctx, name: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.describe_function(Name=name)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchFunctionExists":
            raise
        return
    cf.delete_function(Name=name, IfMatch=etag)


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
