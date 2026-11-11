"""deploy-cloudfront-1-cache-policy-invalid-ttl-order-update-rejected-rolls-back."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-1-cache-policy-invalid-ttl-order-update-rejected-rolls-back"
GROUP = "deploy-cfn-cloudfront-rollback-drift"
SERVICES = ["cloudfront"]

_MIN_TTL, _DEFAULT_TTL, _MAX_TTL = 1, 100, 1000
_INVALID_DEFAULT_TTL = 5000  # above MaxTTL: violates MinTTL <= DefaultTTL <= MaxTTL
_VALID_DEFAULT_TTL = 200


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack update setting a CachePolicy's DefaultTTL above MaxTTL fails (InvalidRequest) and
    rolls back with the policy's Id and original DefaultTTL intact; a valid DefaultTTL then applies
    in place.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")

    policy_name = ctx.unique_name("sim2real-cfttl-cp-")
    stack_name = ctx.unique_name("sim2real-cfttl-stack-")

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
    before = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert before["DefaultTTL"] == _DEFAULT_TTL, f"deployed DefaultTTL wrong: {before!r}"

    # The resource schema does not encode the TTL order, so CloudFront refuses it during the update.
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(),
                     Parameters=_params(policy_name, _INVALID_DEFAULT_TTL))
    ustatus = _poll_until(lambda: _stack_status(cfn, stack_name),
                          lambda s: not s.endswith("_IN_PROGRESS"),
                          timeout_s=600.0, interval_s=5.0, description=f"bad update {stack_name}")
    assert ustatus == "UPDATE_ROLLBACK_COMPLETE", (
        f"DefaultTTL={_INVALID_DEFAULT_TTL} > MaxTTL={_MAX_TTL} must roll the update back, "
        f"got {ustatus!r}"
    )
    failed = [e for e in _stack_events(cfn, stack_name)
              if e["LogicalResourceId"] == "Policy" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert len(failed) == 1, f"Policy must be UPDATE_FAILED exactly once, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    # The handler does not relay CloudFront's TTL-order text; the attribution to the TTL rule is
    # the differential below: the ONLY change is DefaultTTL, and a valid DefaultTTL then lands.
    for needle in ("Invalid request provided: AWS::CloudFront::CachePolicy",
                   "HandlerErrorCode: InvalidRequest"):
        assert needle in reason, f"Policy UPDATE_FAILED reason must carry {needle!r}, got {reason!r}"

    # ---- the effect is absent: same id, original value ----
    assert _physical_id(cfn, stack_name, "Policy") == policy_id, "the rollback replaced the policy"
    kept = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert (kept["MinTTL"], kept["DefaultTTL"], kept["MaxTTL"]) == (
        _MIN_TTL, _DEFAULT_TTL, _MAX_TTL), (
        f"a refused update must leave the TTLs at {(_MIN_TTL, _DEFAULT_TTL, _MAX_TTL)!r}, "
        f"got {(kept['MinTTL'], kept['DefaultTTL'], kept['MaxTTL'])!r}"
    )

    # ---- positive control: a valid DefaultTTL on the same stack lands in place ----
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(),
                     Parameters=_params(policy_name, _VALID_DEFAULT_TTL))
    cstatus = _poll_until(lambda: _stack_status(cfn, stack_name),
                          lambda s: not s.endswith("_IN_PROGRESS"),
                          timeout_s=600.0, interval_s=5.0, description=f"good update {stack_name}")
    assert cstatus == "UPDATE_COMPLETE", f"a valid DefaultTTL update must complete, got {cstatus!r}"
    assert _physical_id(cfn, stack_name, "Policy") == policy_id, "valid update replaced the policy"
    good = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert good["DefaultTTL"] == _VALID_DEFAULT_TTL, (
        f"GetCachePolicyConfig must show DefaultTTL={_VALID_DEFAULT_TTL}, got {good!r}"
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



def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]





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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
