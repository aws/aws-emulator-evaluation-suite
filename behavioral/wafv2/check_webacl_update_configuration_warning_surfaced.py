"""webacl-update-configuration-warning-surfaced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-update-configuration-warning-surfaced"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWebACL accepts a Body-inspecting rule without OversizeHandling, persisting it with the
    CONTINUE default and a new LockToken; an OversizeHandling outside the enum fails with
    ValidationException and the exact message, leaving the rules and LockToken unchanged.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-webacl-")

    def _visibility(metric):
        return {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": metric,
        }

    base_rule = {
        "Name": "base-geo",
        "Priority": 0,
        "Action": {"Count": {}},
        "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
        "VisibilityConfig": _visibility("base-geo"),
    }

    created = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Rules=[base_rule],
        VisibilityConfig=_visibility(name),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    web_acl_id = created["Id"]

    def _get():
        return wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)

    def _delete():
        current = _get()
        wafv2.delete_web_acl(Name=name, Scope=scope, Id=web_acl_id, LockToken=current["LockToken"])

    ctx.on_cleanup(_delete)

    def _body_rule(oversize_handling):
        field_to_match = (
            {"Body": {}} if oversize_handling is None else {"Body": {"OversizeHandling": oversize_handling}}
        )
        return {
            "Name": "body-inspect",
            "Priority": 1,
            "Action": {"Count": {}},
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": b"attack",
                    "FieldToMatch": field_to_match,
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "CONTAINS",
                }
            },
            "VisibilityConfig": _visibility("body-inspect"),
        }

    before = _get()
    lock_token_before = before["LockToken"]

    # (1) Omitting OversizeHandling on a Body FieldToMatch is committed, not
    # rejected -- the documented WAFConfigurationWarningException does not
    # fire for this direct API call; the default (CONTINUE) is applied
    # silently.
    updated = wafv2.update_web_acl(
        Name=name,
        Scope=scope,
        Id=web_acl_id,
        LockToken=lock_token_before,
        DefaultAction={"Allow": {}},
        Rules=[base_rule, _body_rule(None)],
        VisibilityConfig=_visibility(name),
    )
    assert updated["NextLockToken"] != lock_token_before, (
        f"expected NextLockToken to advance past {lock_token_before!r}, "
        f"got {updated['NextLockToken']!r}"
    )

    after_success = _get()
    rule_names = sorted(r["Name"] for r in after_success["WebACL"]["Rules"])
    assert rule_names == ["base-geo", "body-inspect"], (
        f"expected rules ['base-geo', 'body-inspect'] to be persisted, got {rule_names!r}"
    )
    persisted_body = next(
        r for r in after_success["WebACL"]["Rules"] if r["Name"] == "body-inspect"
    )["Statement"]["ByteMatchStatement"]["FieldToMatch"]["Body"]
    assert persisted_body.get("OversizeHandling", "CONTINUE") == "CONTINUE", (
        f"expected OversizeHandling to default to CONTINUE, got {persisted_body!r}"
    )

    lock_token_after_success = after_success["LockToken"]

    # (2) The distinct negative boundary: an out-of-enum OversizeHandling
    # value on the very same field IS rejected, and the update is not
    # committed (rule set and lock token both unchanged).
    try:
        wafv2.update_web_acl(
            Name=name,
            Scope=scope,
            Id=web_acl_id,
            LockToken=lock_token_after_success,
            DefaultAction={"Allow": {}},
            Rules=[base_rule, _body_rule("NOT_A_REAL_VALUE")],
            VisibilityConfig=_visibility(name),
        )
        raise AssertionError("UpdateWebACL unexpectedly accepted an invalid OversizeHandling value")
    except ClientError as e:
        error = e.response["Error"]
        assert error["Code"] == "ValidationException", (
            f"unexpected error for invalid OversizeHandling: {error}"
        )
        assert error["Message"] == (
            # the member path is 1-based: body-inspect is the second rule
            "1 validation error detected: Value 'NOT_A_REAL_VALUE' at "
            "'rules.2.member.statement.byteMatchStatement.fieldToMatch.body.oversizeHandling' "
            "failed to satisfy constraint: Member must satisfy enum value set: "
            "[MATCH, NO_MATCH, CONTINUE]"
        ), f"unexpected message for invalid OversizeHandling: {error}"

    after_rejected = _get()
    assert after_rejected["LockToken"] == lock_token_after_success, (
        f"expected LockToken to remain {lock_token_after_success!r} after the "
        f"rejected update, got {after_rejected['LockToken']!r}"
    )
    rejected_rule_names = sorted(r["Name"] for r in after_rejected["WebACL"]["Rules"])
    assert rejected_rule_names == ["base-geo", "body-inspect"], (
        f"expected rules to remain ['base-geo', 'body-inspect'] after the "
        f"rejected update, got {rejected_rule_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
