"""deploy-cloudfront-1-distribution-nonexistent-cache-policy-rejected-rolls-back."""
from __future__ import annotations

import json
import sys
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-1-distribution-nonexistent-cache-policy-rejected-rolls-back"
GROUP = "deploy-cfn-cloudfront-rollback-drift"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Distribution referencing a nonexistent cache policy fails with CREATE_FAILED and the stack
    rolls back to ROLLBACK_COMPLETE, deleting the CachePolicy and OriginAccessControl it had already
    created (NoSuchCachePolicy / NoSuchOriginAccessControl from CloudFront).
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")

    policy_name = ctx.unique_name("sim2real-cfrb-cp-")
    oac_name = ctx.unique_name("sim2real-cfrb-oac-")
    stack_name = ctx.unique_name("sim2real-cfrb-stack-")
    bogus_policy_id = str(uuid.uuid4())

    # Registered BEFORE the create: name-scoped cleanups (run last, LIFO) catch anything the
    # rollback or the stack delete failed to remove, and the stack delete runs first.
    ctx.on_cleanup(lambda: _reap_cache_policy_by_name(cf, policy_name))
    ctx.on_cleanup(lambda: _reap_oac_by_name(cf, oac_name))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    template = {
        "Resources": {
            "Policy": {
                "Type": "AWS::CloudFront::CachePolicy",
                "Properties": {"CachePolicyConfig": _policy_config(policy_name, 1, 100, 1000)},
            },
            "OAC": {
                "Type": "AWS::CloudFront::OriginAccessControl",
                "Properties": {
                    "OriginAccessControlConfig": {
                        "Name": oac_name,
                        "Description": "sim2real rollback check",
                        "OriginAccessControlOriginType": "s3",
                        "SigningBehavior": "always",
                        "SigningProtocol": "sigv4",
                    }
                },
            },
            "Dist": {
                "Type": "AWS::CloudFront::Distribution",
                # Force the two earlier resources to be CREATED before the distribution fails.
                "DependsOn": ["Policy", "OAC"],
                "Properties": {
                    "DistributionConfig": {
                        "Enabled": False,
                        "Comment": "sim2real rollback check - must never be created",
                        "Origins": [{
                            "Id": "origin1",
                            "DomainName": "example.com",
                            "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"},
                        }],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "origin1",
                            "ViewerProtocolPolicy": "allow-all",
                            "CachePolicyId": bogus_policy_id,
                        },
                    }
                },
            },
        }
    }

    ctx.verify_account_safety()
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _poll_until(lambda: _stack_status(cfn, stack_name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=900.0, interval_s=5.0, description=f"stack {stack_name}")
    assert status == "ROLLBACK_COMPLETE", (
        f"a stack whose Distribution references nonexistent cache policy {bogus_policy_id!r} "
        f"must end ROLLBACK_COMPLETE, got {status!r}"
    )

    events = _stack_events(cfn, stack_name)  # oldest first
    by_lid: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        by_lid.setdefault(e["LogicalResourceId"], []).append(e)

    # ---- positive control: the earlier resources really existed ----
    created: dict[str, dict[str, Any]] = {}
    for lid in ("Policy", "OAC"):
        cc = [e for e in by_lid.get(lid, []) if e["ResourceStatus"] == "CREATE_COMPLETE"]
        assert len(cc) == 1, (
            f"{lid} must reach CREATE_COMPLETE exactly once before the rollback, events were "
            f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in by_lid.get(lid, [])]!r}"
        )
        assert cc[0].get("PhysicalResourceId"), f"{lid} CREATE_COMPLETE carries no physical id: {cc[0]!r}"
        created[lid] = cc[0]
    policy_id = created["Policy"]["PhysicalResourceId"]
    oac_id = created["OAC"]["PhysicalResourceId"]

    # ---- the failing resource and its reason ----
    failed = [e for e in by_lid.get("Dist", []) if e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, (
        f"Dist must be CREATE_FAILED exactly once, events were "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in by_lid.get('Dist', [])]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    # CloudFront's NoSuchCachePolicy (404) surfaced through the resource handler as InvalidRequest.
    for needle in ("The specified cache policy does not exist.", "Status Code: 404",
                   "HandlerErrorCode: InvalidRequest"):
        assert needle in reason, (
            f"Dist CREATE_FAILED reason must name the missing cache policy ({needle!r}), got {reason!r}"
        )
    dist_ids = [e.get("PhysicalResourceId") for e in by_lid["Dist"] if e.get("PhysicalResourceId")]
    assert not dist_ids, f"no distribution may have been created, but Dist carried ids {dist_ids!r}"
    stack_reasons = [e.get("ResourceStatusReason") for e in by_lid.get(stack_name, [])
                     if e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    assert stack_reasons == [
        "The following resource(s) failed to create: [Dist]. Rollback requested by user."
    ], f"the stack's ROLLBACK_IN_PROGRESS must name Dist as the only failure, got {stack_reasons!r}"
    for lid in ("Policy", "OAC"):
        assert created[lid]["Timestamp"] <= failed[0]["Timestamp"], (
            f"{lid} CREATE_COMPLETE at {created[lid]['Timestamp']} must precede Dist CREATE_FAILED "
            f"at {failed[0]['Timestamp']} (DependsOn)"
        )

    # ---- rollback deleted the earlier resources, per the stack ----
    for lid in ("Policy", "OAC"):
        statuses = [e["ResourceStatus"] for e in by_lid[lid]]
        assert statuses[-1] == "DELETE_COMPLETE", (
            f"rollback must end {lid} DELETE_COMPLETE, its event sequence was {statuses!r}"
        )
        dc = [e for e in by_lid[lid] if e["ResourceStatus"] == "DELETE_COMPLETE"][-1]
        assert dc["Timestamp"] >= failed[0]["Timestamp"], (
            f"{lid} was deleted at {dc['Timestamp']}, before the failure at {failed[0]['Timestamp']}"
        )

    # ---- ... and per CloudFront itself, off the stack ----
    _poll_for_error_code(lambda: cf.get_cache_policy(Id=policy_id), "NoSuchCachePolicy",
                         f"GetCachePolicy({policy_id}) after rollback", timeout_s=120.0)
    _poll_for_error_code(lambda: cf.get_origin_access_control(Id=oac_id),
                         "NoSuchOriginAccessControl",
                         f"GetOriginAccessControl({oac_id}) after rollback", timeout_s=120.0)


_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _policy_config(name: str, min_ttl: int, default_ttl: int, max_ttl: int) -> dict[str, Any]:
    return {
        "Name": name,
        "Comment": "sim2real cfn rollback/drift check",
        "MinTTL": min_ttl,
        "DefaultTTL": default_ttl,
        "MaxTTL": max_ttl,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "CookiesConfig": {"CookieBehavior": "none"},
            "HeadersConfig": {"HeaderBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _poll_for_error_code(fn, code: str, description: str, *, timeout_s=120.0,
                         interval_s=5.0) -> None:
    """Poll fn() until it raises exactly `code`; a different code fails immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            got_ok = fn()
        except ClientError as exc:
            got = exc.response.get("Error", {}).get("Code", "")
            assert got == code, f"{description}: expected {code!r}, got {got!r} ({exc})"
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: still succeeding after {timeout_s}s; expected {code!r}; "
                f"last response {got_ok!r}")
        time.sleep(interval_s)


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _stack_events(cfn, name: str) -> list[dict[str, Any]]:
    """Every stack event, paginated, oldest first."""
    out: list[dict[str, Any]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page.get("StackEvents", []))
    return list(reversed(out))


def _delete_stack_and_wait(cfn, name: str, *, timeout_s=900.0) -> None:
    """Teardown: delete the stack and wait; a failure raises."""
    try:
        if _stack_status(cfn, name) == "GONE":
            return
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0, description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(f"cloudformation stack {name} ended DELETE_FAILED")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"cloudformation stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


def _reap_cache_policy_by_name(cf, name: str) -> None:
    """Delete any custom cache policy still carrying `name`, then raise naming it: the stack leaked it."""
    survivors = []
    marker = None
    while True:
        kw: dict[str, Any] = {"Type": "custom"}
        if marker:
            kw["Marker"] = marker
        lst = cf.list_cache_policies(**kw)["CachePolicyList"]
        for item in lst.get("Items", []) or []:
            pol = item["CachePolicy"]
            if pol["CachePolicyConfig"]["Name"] == name:
                survivors.append(pol["Id"])
                try:
                    etag = cf.get_cache_policy(Id=pol["Id"])["ETag"]
                    cf.delete_cache_policy(Id=pol["Id"], IfMatch=etag)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
                        raise
        marker = lst.get("NextMarker")
        if not marker:
            break
    if survivors:
        raise RuntimeError(f"cache policy {name} id(s) {survivors} survived the stack; deleted them")


def _reap_oac_by_name(cf, name: str) -> None:
    """Delete any origin access control still carrying `name`, then raise naming it: the stack
    leaked it."""
    survivors = []
    marker = None
    while True:
        kw: dict[str, Any] = {}
        if marker:
            kw["Marker"] = marker
        lst = cf.list_origin_access_controls(**kw)["OriginAccessControlList"]
        for item in lst.get("Items", []) or []:
            if item["Name"] == name:
                survivors.append(item["Id"])
                try:
                    etag = cf.get_origin_access_control(Id=item["Id"])["ETag"]
                    cf.delete_origin_access_control(Id=item["Id"], IfMatch=etag)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                        raise
        marker = lst.get("NextMarker")
        if not marker:
            break
    if survivors:
        raise RuntimeError(f"origin access control {name} id(s) {survivors} survived the stack; "
                           f"deleted them")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
