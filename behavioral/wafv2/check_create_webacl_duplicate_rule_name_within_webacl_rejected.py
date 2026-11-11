"""create-webacl-duplicate-rule-name-within-webacl-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-webacl-duplicate-rule-name-within-webacl-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWebACL with two rules of the same Name fails with WAFInvalidParameterException and the exact message and
    creates no WebACL, while two distinctly named rules create a WebACL holding both."""
    wafv2 = ctx.client("wafv2")

    dup_name = ctx.unique_name("sim2real-behav-dup-")
    webacl_name = ctx.unique_name("sim2real-behav-webacl-")

    def _rule(name: str, priority: int) -> dict:
        return {
            "Name": name,
            "Priority": priority,
            "Action": {"Count": {}},
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": name.replace("-", ""),
            },
        }

    duplicate_rules = [_rule(dup_name, 0), _rule(dup_name, 1)]

    code, message = _error(
        lambda: wafv2.create_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility_config(webacl_name),
            Rules=duplicate_rules,
        )
    )
    # A WebACL containing two rules
    # with the identical Name is rejected as a malformed request
    # (WAFInvalidParameterException), not the resource-level
    # WAFDuplicateItemException (which applies to e.g. duplicate resource
    # names across independent CreateXxx calls).
    assert code == "WAFInvalidParameterException", f"expected WAFInvalidParameterException, got {code!r}"
    assert message == (
        "Error reason: You have duplicated some of the information in the parameter., "
        f"field: RULE, parameter: {dup_name}"
    ), message

    # Effect absent: no WebACL with this name exists (creation did not partially land).
    names = {w["Name"] for w in wafv2.list_web_acls(Scope="REGIONAL")["WebACLs"]}
    assert webacl_name not in names, f"expected no WebACL named {webacl_name!r} after rejection, but ListWebACLs returned it"

    # Positive control: distinctly-named rules are accepted.
    good_rules = [_rule(f"{dup_name}-a", 0), _rule(f"{dup_name}-b", 1)]
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config(webacl_name),
        Rules=good_rules,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )["Summary"]
    ctx.on_cleanup(
        lambda: wafv2.delete_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            Id=created["Id"],
            LockToken=wafv2.get_web_acl(
                Name=webacl_name, Scope="REGIONAL", Id=created["Id"]
            )["LockToken"],
        )
    )
    fetched = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=created["Id"])
    got_names = sorted(r["Name"] for r in fetched["WebACL"]["Rules"])
    want_names = sorted(r["Name"] for r in good_rules)
    assert got_names == want_names, f"expected rule names {want_names!r}, got {got_names!r}"


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name.replace(".", ""),
    }


def _error(fn: Callable[[], Any]):
    """Return (code, message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
