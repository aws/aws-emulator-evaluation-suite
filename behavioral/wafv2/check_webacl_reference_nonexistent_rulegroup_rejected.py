"""webacl-reference-nonexistent-rulegroup-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-reference-nonexistent-rulegroup-rejected"
GROUP = 'webacl'
SERVICES = ['wafv2']

# REGIONAL is usable from any endpoint/region; CLOUDFRONT scope requires us-east-1.
SCOPE = "REGIONAL"


def _error(fn):
    """Call fn(); return the botocore ``Error`` (code and message) if a ClientError is raised.
    An unexpected success raises, so acceptance never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _rule_group_reference_rule(name, arn, priority=0):
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"RuleGroupReferenceStatement": {"ARN": arn}},
        "OverrideAction": {"None": {}},
        "VisibilityConfig": _visibility_config(name),
    }


def _delete_by_name(w, kind, name, scope=SCOPE):
    """Teardown for a web ACL or rule group known only by name: resolve its Id through List*, then
    delete with a fresh LockToken. Never created or already gone is clean; a reference still being
    released or a transient error is retried every 2 s for 15 s; anything else raises."""
    list_key = {"web_acl": "WebACLs", "rule_group": "RuleGroups"}[kind]
    retryable = {"WAFAssociatedItemException", "WAFOptimisticLockException",
                 "WAFUnavailableEntityException", "ThrottlingException"}
    kwargs = {"Scope": scope, "Limit": 100}
    while True:
        page = getattr(w, f"list_{kind}s")(**kwargs)
        for summary in page.get(list_key, []):
            if summary["Name"] != name:
                continue
            deadline = time.monotonic() + 15.0
            while True:
                try:
                    got = getattr(w, f"get_{kind}")(Name=name, Scope=scope, Id=summary["Id"])
                    getattr(w, f"delete_{kind}")(
                        Name=name, Scope=scope, Id=summary["Id"], LockToken=got["LockToken"]
                    )
                    return
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code == "WAFNonexistentItemException":
                        return
                    if code not in retryable or time.monotonic() >= deadline:
                        raise
                time.sleep(2)
        if not page.get("NextMarker") or not page.get(list_key):
            return
        kwargs["NextMarker"] = page["NextMarker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWebACL with a rule referencing a nonexistent RuleGroup ARN is rejected and the WebACL
    is absent from ListWebACLs, while the same shape against a real RuleGroup succeeds."""
    w = ctx.client("wafv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    rg_name = ctx.unique_name("sim2real-behav-waf-rg-good-")
    ctx.on_cleanup(lambda: _delete_by_name(w, "rule_group", rg_name))
    rg = w.create_rule_group(
        Name=rg_name, Scope=SCOPE, Capacity=10, Rules=[],
        VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
    )
    rg_arn = rg["Summary"]["ARN"]

    good_name = ctx.unique_name("sim2real-behav-waf-wacl-goodref-")
    ctx.on_cleanup(lambda: _delete_by_name(w, "web_acl", good_name))
    good_rule = _rule_group_reference_rule("use-real-rg", rg_arn, priority=0)

    def _make_good_web_acl():
        return w.create_web_acl(
            Name=good_name,
            Scope=SCOPE,
            DefaultAction={"Allow": {}},
            Rules=[good_rule],
            VisibilityConfig=_visibility_config(good_name),
        )

    # A just-created RuleGroup can briefly be unresolvable from a new WebACL
    # (WAFUnavailableEntityException) due to control-plane propagation lag; poll with a
    # bounded retry rather than a single attempt.
    good_resp = None
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            good_resp = _make_good_web_acl()
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "WAFUnavailableEntityException":
                raise
            last_err = exc
            time.sleep(3)
    if good_resp is None:
        raise AssertionError(
            f"positive control failed: CreateWebACL referencing the real RuleGroup {rg_arn} "
            f"kept failing with WAFUnavailableEntityException within 60s: {last_err!r}"
        )
    assert good_resp["Summary"]["Name"] == good_name, (
        f"positive control failed: CreateWebACL referencing the real RuleGroup {rg_arn} "
        f"should succeed, got {good_resp!r}"
    )

    fake_arn = (
        f"arn:aws:wafv2:{ctx.region}:{account_id}:regional/rulegroup/"
        f"{ctx.unique_name('sim2real-behav-waf-ghost-rg-')}/00000000-0000-0000-0000-000000000000"
    )
    bad_rule = _rule_group_reference_rule("use-ghost-rg", fake_arn, priority=0)
    bad_name = ctx.unique_name("sim2real-behav-waf-wacl-badref-")
    # Registered up front so an unexpectedly-accepted CreateWebACL cannot leak.
    ctx.on_cleanup(lambda: _delete_by_name(w, "web_acl", bad_name))

    error = _error(
        lambda: w.create_web_acl(
            Name=bad_name,
            Scope=SCOPE,
            DefaultAction={"Allow": {}},
            Rules=[bad_rule],
            VisibilityConfig=_visibility_config(bad_name),
        )
    )
    assert error.get("Code") == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException for a Rule referencing a nonexistent "
        f"RuleGroup ARN, got {error!r}"
    )
    assert error.get("Message") == (
        "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
    ), f"unexpected message: {error!r}"

    # Independent read at the destination: the rejected WebACL must not exist.
    listed = [s["Name"] for s in w.list_web_acls(Scope=SCOPE, Limit=100).get("WebACLs", [])]
    assert bad_name not in listed, (
        f"CreateWebACL was rejected but {bad_name!r} still appears in ListWebACLs: {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
