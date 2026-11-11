"""update-resource-conflicting-name-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-resource-conflicting-name-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


def _cache_policy_config(name: str) -> dict:
    return {
        "Comment": "sim2real behavioral check",
        "DefaultTTL": 50,
        "MaxTTL": 100,
        "MinTTL": 1,
        "Name": name,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "CookiesConfig": {"CookieBehavior": "none"},
            "EnableAcceptEncodingGzip": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Renaming a CloudFront cache policy via UpdateResource to another policy's Name ends FAILED
    with ServiceInternalError and leaves the native name unchanged; an unused name succeeds."""
    cc = ctx.client("cloudcontrol")
    cf = ctx.client("cloudfront")

    name_a = ctx.unique_name("sim2real-behav-cccpa-")
    name_b = ctx.unique_name("sim2real-behav-cccpb-")

    progress_a = cc.create_resource(
        TypeName="AWS::CloudFront::CachePolicy",
        DesiredState=json.dumps({"CachePolicyConfig": _cache_policy_config(name_a)}),
    )["ProgressEvent"]
    final_a = _poll_request_status(ctx, progress_a["RequestToken"])
    assert final_a["OperationStatus"] == "SUCCESS", f"create A failed: {final_a}"
    id_a = final_a["Identifier"]
    ctx.on_cleanup(lambda: _delete_cache_policy_if_exists(cf, id_a))

    progress_b = cc.create_resource(
        TypeName="AWS::CloudFront::CachePolicy",
        DesiredState=json.dumps({"CachePolicyConfig": _cache_policy_config(name_b)}),
    )["ProgressEvent"]
    final_b = _poll_request_status(ctx, progress_b["RequestToken"])
    assert final_b["OperationStatus"] == "SUCCESS", f"create B failed: {final_b}"
    id_b = final_b["Identifier"]
    ctx.on_cleanup(lambda: _delete_cache_policy_if_exists(cf, id_b))

    patch = json.dumps(
        [{"op": "replace", "path": "/CachePolicyConfig/Name", "value": name_b}]
    )
    rename_progress = cc.update_resource(
        TypeName="AWS::CloudFront::CachePolicy", Identifier=id_a, PatchDocument=patch
    )["ProgressEvent"]
    rename_final = _poll_request_status(ctx, rename_progress["RequestToken"])
    assert rename_final["OperationStatus"] == "FAILED", f"unexpected final status: {rename_final}"
    # CloudFront's own name-collision error on UpdateCachePolicy doesn't map to a
    # dedicated CC error code; it surfaces as a downstream-service internal error.
    expected = (
        "ServiceInternalError",
        "Internal error reported from downstream service during operation 'AWS::CloudFront::CachePolicy'.",
    )
    assert (rename_final.get("ErrorCode"), rename_final.get("StatusMessage")) == expected, (
        f"expected ErrorCode and StatusMessage {expected!r}, got {rename_final}"
    )

    # Read at CloudFront itself: Cloud Control's GetResource only proves its own view.
    name_a_now = cf.get_cache_policy(Id=id_a)["CachePolicy"]["CachePolicyConfig"]["Name"]
    assert name_a_now == name_a, f"expected native name {name_a!r} unchanged, got {name_a_now!r}"

    name_a_new = ctx.unique_name("sim2real-behav-cccpa2-")
    control_patch = json.dumps(
        [{"op": "replace", "path": "/CachePolicyConfig/Name", "value": name_a_new}]
    )
    control_progress = cc.update_resource(
        TypeName="AWS::CloudFront::CachePolicy", Identifier=id_a, PatchDocument=control_patch
    )["ProgressEvent"]
    control_final = _poll_request_status(ctx, control_progress["RequestToken"])
    assert control_final["OperationStatus"] == "SUCCESS", f"control rename failed: {control_final}"
    name_a_final = cf.get_cache_policy(Id=id_a)["CachePolicy"]["CachePolicyConfig"]["Name"]
    assert name_a_final == name_a_new, (
        f"expected native name {name_a_new!r} after the control rename, got {name_a_final!r}"
    )


def _delete_cache_policy_if_exists(cf, policy_id: str) -> None:
    try:
        etag = cf.get_cache_policy(Id=policy_id)["ETag"]
        cf.delete_cache_policy(Id=policy_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
            raise


def _poll_request_status(ctx, token, timeout_s=120.0, interval_s=3.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal status; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

