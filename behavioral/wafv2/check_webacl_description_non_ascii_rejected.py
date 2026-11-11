"""webacl-description-non-ascii-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webacl-description-non-ascii-rejected"
GROUP = "representation"
SERVICES = ["wafv2"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ASCII WebACL Description round-trips; UpdateWebACL with a multi-byte Description fails with
    ValidationException and the exact pattern message, leaving the Description and LockToken unchanged.
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-webacl-desc-")
    scope = "REGIONAL"
    vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}

    ascii_desc = "Regional WAF ACL, desc-01 v1.0 test_env"
    created = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Description=ascii_desc,
        VisibilityConfig=vis,
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    summary = created["Summary"]
    acl_id = summary["Id"]

    def _cleanup():
        try:
            cur = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            wafv2.delete_web_acl(Name=name, Scope=scope, Id=acl_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: ASCII Description round-trips byte-for-byte.
    assert summary["Description"] == ascii_desc, (
        f"CreateWebACL altered the ASCII Description: {summary['Description']!r}"
    )
    got1 = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    assert got1["WebACL"]["Description"] == ascii_desc, (
        f"Create round-trip altered the ASCII Description: {got1['WebACL']['Description']!r}"
    )

    # Break exactly one thing: attempt to update with a non-ASCII Description.
    unicode_desc = "网站防火墙 描述二 v2"

    def _attempt_unicode_update():
        return wafv2.update_web_acl(
            Name=name,
            Scope=scope,
            Id=acl_id,
            DefaultAction={"Allow": {}},
            Description=unicode_desc,
            VisibilityConfig=vis,
            LockToken=got1["LockToken"],
        )

    code, message = _error_code(_attempt_unicode_update)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value '" + unicode_desc + "' at 'description' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        r"^[\w+=:#@/\-,\.][\w+=:#@/\-,\.\s]+[\w+=:#@/\-,\.]$"
    ), f"unexpected ValidationException message {message!r}"

    # Effect must be absent: the original ASCII Description is unchanged.
    got2 = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
    assert got2["WebACL"]["Description"] == ascii_desc, (
        f"rejected unicode update leaked through: {got2['WebACL']['Description']!r}"
    )
    assert got2["LockToken"] == got1["LockToken"], (
        f"rejected update still advanced the LockToken: {got1['LockToken']!r} -> {got2['LockToken']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
