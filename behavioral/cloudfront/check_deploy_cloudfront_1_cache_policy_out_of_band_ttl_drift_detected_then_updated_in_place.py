"""deploy-cloudfront-1-cache-policy-out-of-band-ttl-drift-detected-then-updated-in-place."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-1-cache-policy-out-of-band-ttl-drift-detected-then-updated-in-place"
GROUP = "deploy-cfn-cloudfront-rollback-drift"
SERVICES = ["cloudfront"]

_MIN_TTL, _DEFAULT_TTL, _MAX_TTL = 1, 100, 1000
_DRIFTED_MIN_TTL = 5
_UPDATED_DEFAULT_TTL = 200


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An out-of-band MinTTL change (1 -> 5) to a stack's CachePolicy is reported DRIFTED with a
    NOT_EQUAL difference on CachePolicyConfig.MinTTL; a later DefaultTTL stack update applies in
    place (same Id).
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")

    policy_name = ctx.unique_name("sim2real-cfdr-cp-")
    stack_name = ctx.unique_name("sim2real-cfdr-stack-")

    # Registered BEFORE the create: the name-scoped cleanup runs last (LIFO) and catches a policy
    # the stack delete left behind; the stack delete runs first.
    ctx.on_cleanup(lambda: _reap_cache_policy_by_name(cf, policy_name))
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    ctx.verify_account_safety()
    cfn.create_stack(StackName=stack_name, TemplateBody=_template(),
                     Parameters=_params(policy_name, _DEFAULT_TTL),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _poll_until(lambda: _stack_status(cfn, stack_name), lambda s: s in _CREATE_TERMINAL,
                         timeout_s=600.0, interval_s=5.0, description=f"create {stack_name}")
    assert status == "CREATE_COMPLETE", f"setup stack ended {status!r}"

    policy_id = _physical_id(cfn, stack_name, "Policy")
    got = cf.get_cache_policy_config(Id=policy_id)
    cfg, etag0 = got["CachePolicyConfig"], got["ETag"]
    assert (cfg["MinTTL"], cfg["DefaultTTL"], cfg["MaxTTL"]) == (_MIN_TTL, _DEFAULT_TTL, _MAX_TTL), (
        f"deployed policy TTLs are {(cfg['MinTTL'], cfg['DefaultTTL'], cfg['MaxTTL'])!r}"
    )

    # ---- baseline: a freshly deployed stack is IN_SYNC ----
    base = _detect(cfn, stack_name)
    assert base["StackDriftStatus"] == "IN_SYNC", f"fresh stack must be IN_SYNC, got {base!r}"

    # ---- out-of-band mutation through CloudFront, with the current ETag ----
    cfg["MinTTL"] = _DRIFTED_MIN_TTL
    upd = cf.update_cache_policy(Id=policy_id, IfMatch=etag0, CachePolicyConfig=cfg)
    assert upd["CachePolicy"]["Id"] == policy_id, f"UpdateCachePolicy changed the id: {upd!r}"
    assert upd["ETag"] != etag0, f"UpdateCachePolicy must advance the ETag, still {etag0!r}"
    live = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert live["MinTTL"] == _DRIFTED_MIN_TTL, f"out-of-band MinTTL not applied: {live!r}"

    # ---- drift detection sees it ----
    det = _detect(cfn, stack_name)
    assert det["StackDriftStatus"] == "DRIFTED", f"stack must be DRIFTED after the edit: {det!r}"
    assert det["DriftedStackResourceCount"] == 1, f"exactly one drifted resource expected: {det!r}"

    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(cfn, stack_name)}
    assert set(drifts) == {"Policy"}, f"drift must report on Policy only, got {sorted(drifts)!r}"
    pd = drifts["Policy"]
    assert pd["StackResourceDriftStatus"] == "MODIFIED", f"Policy must be MODIFIED: {pd!r}"
    assert pd["PhysicalResourceId"] == policy_id, f"drift names the wrong policy: {pd!r}"
    diffs = {d["PropertyPath"]: d for d in pd.get("PropertyDifferences", [])}
    assert set(diffs) == {"/CachePolicyConfig/MinTTL"}, (
        f"the only property difference must be CachePolicyConfig.MinTTL, got {sorted(diffs)!r}"
    )
    mt = diffs["/CachePolicyConfig/MinTTL"]
    # Compared numerically: real AWS renders the actual side as '5.0' and the expected as '1'.
    assert (float(mt["ExpectedValue"]), float(mt["ActualValue"]), mt["DifferenceType"]) == (
        _MIN_TTL, _DRIFTED_MIN_TTL, "NOT_EQUAL"), (
        f"MinTTL drift must be expected={_MIN_TTL} actual={_DRIFTED_MIN_TTL} NOT_EQUAL, got {mt!r}"
    )
    assert json.loads(pd["ExpectedProperties"])["CachePolicyConfig"]["MinTTL"] == _MIN_TTL, (
        f"ExpectedProperties must carry the template MinTTL: {pd['ExpectedProperties']!r}"
    )
    assert json.loads(pd["ActualProperties"])["CachePolicyConfig"]["MinTTL"] == _DRIFTED_MIN_TTL, (
        f"ActualProperties must carry the live MinTTL: {pd['ActualProperties']!r}"
    )

    # ---- in-place stack update of a mutable property ----
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(),
                     Parameters=_params(policy_name, _UPDATED_DEFAULT_TTL))
    ustatus = _poll_until(lambda: _stack_status(cfn, stack_name),
                          lambda s: not s.endswith("_IN_PROGRESS"),
                          timeout_s=600.0, interval_s=5.0, description=f"update {stack_name}")
    assert ustatus == "UPDATE_COMPLETE", f"DefaultTTL update must UPDATE_COMPLETE, got {ustatus!r}"
    assert _physical_id(cfn, stack_name, "Policy") == policy_id, (
        "a DefaultTTL change must update the policy in place, but the physical id moved from "
        f"{policy_id!r} to {_physical_id(cfn, stack_name, 'Policy')!r}"
    )
    after = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert after["DefaultTTL"] == _UPDATED_DEFAULT_TTL, (
        f"GetCachePolicyConfig must show DefaultTTL={_UPDATED_DEFAULT_TTL}, got {after!r}"
    )
    assert after["Name"] == policy_name, f"policy name changed across the update: {after!r}"
    # The update writes the template's whole config, so the out-of-band MinTTL is overwritten.
    assert after["MinTTL"] == _MIN_TTL, (
        f"the stack update must reconcile MinTTL back to the template's {_MIN_TTL}, got {after!r}"
    )
    resync = _detect(cfn, stack_name)
    assert resync["StackDriftStatus"] == "IN_SYNC", (
        f"after the update re-applied the template the stack must be IN_SYNC again: {resync!r}"
    )


_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
                    "DELETE_COMPLETE", "DELETE_FAILED", "GONE"}


def _template() -> str:
    return json.dumps({
        "Parameters": {"PolicyName": {"Type": "String"}, "DefaultTTL": {"Type": "Number"}},
        "Resources": {
            "Policy": {
                "Type": "AWS::CloudFront::CachePolicy",
                "Properties": {"CachePolicyConfig": {
                    "Name": {"Ref": "PolicyName"},
                    "Comment": "sim2real cfn rollback/drift check",
                    "MinTTL": _MIN_TTL,
                    "DefaultTTL": {"Ref": "DefaultTTL"},
                    "MaxTTL": _MAX_TTL,
                    "ParametersInCacheKeyAndForwardedToOrigin": {
                        "EnableAcceptEncodingGzip": False,
                        "CookiesConfig": {"CookieBehavior": "none"},
                        "HeadersConfig": {"HeaderBehavior": "none"},
                        "QueryStringsConfig": {"QueryStringBehavior": "none"},
                    },
                }},
            }
        },
    })


def _params(name: str, default_ttl: int) -> list[dict[str, str]]:
    return [{"ParameterKey": "PolicyName", "ParameterValue": name},
            {"ParameterKey": "DefaultTTL", "ParameterValue": str(default_ttl)}]


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


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _detect(cfn, stack: str) -> dict[str, Any]:
    """Run one drift detection to completion and return its status record."""
    did = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    det = _poll_until(
        lambda: cfn.describe_stack_drift_detection_status(StackDriftDetectionId=did),
        lambda d: d["DetectionStatus"] != "DETECTION_IN_PROGRESS",
        timeout_s=600.0, interval_s=5.0, description=f"drift detection on {stack}")
    assert det["DetectionStatus"] == "DETECTION_COMPLETE", f"drift detection failed: {det!r}"
    return det


def _resource_drifts(cfn, stack: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kw: dict[str, Any] = {"StackName": stack}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        out.extend(page.get("StackResourceDrifts", []))
        token = page.get("NextToken")
        if not token:
            return out


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
