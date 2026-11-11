"""update-webacl-configuration-warning-surfaced."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.client import Config
from botocore.exceptions import ClientError

CHECK = "update-webacl-configuration-warning-surfaced"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWebACL accepts a header-inspecting rule with OversizeHandling and advances the LockToken;
    without OversizeHandling it fails with ValidationException and the exact must-not-be-null message,
    leaving the rules and LockToken unchanged.
    """
    wafv2 = ctx.client("wafv2")
    wafv2_novalidate = _client_without_param_validation(ctx)

    webacl_name = ctx.unique_name("sim2real-behav-webacl-")
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config(webacl_name),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )["Summary"]
    webacl_id = created["Id"]
    initial_lock_token = created["LockToken"]
    ctx.on_cleanup(lambda: _best_effort_delete_webacl(wafv2, webacl_name, webacl_id))

    # Real, always-executed positive path: the fully-specified rule is
    # accepted and its effect is observable.
    good_rule = _header_inspection_rule("good-header-rule", oversize_handling="CONTINUE")
    result = wafv2.update_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        Id=webacl_id,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config(webacl_name),
        Rules=[good_rule],
        LockToken=initial_lock_token,
    )
    assert result["NextLockToken"] != initial_lock_token, (
        f"expected a new LockToken after UpdateWebACL, got the same token "
        f"{initial_lock_token!r} back"
    )

    updated = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    assert [r["Name"] for r in updated["WebACL"]["Rules"]] == ["good-header-rule"], (
        f"expected only ['good-header-rule'] via the independent GetWebACL read, "
        f"got {[r['Name'] for r in updated['WebACL']['Rules']]!r}"
    )
    assert updated["LockToken"] == result["NextLockToken"], (
        f"expected GetWebACL's LockToken to match UpdateWebACL's NextLockToken "
        f"{result['NextLockToken']!r}, got {updated['LockToken']!r}"
    )
    current_lock_token = updated["LockToken"]

    # Negative: send the shape-required-but-omitted OversizeHandling field
    # over the wire (bypassing boto3's own client-side validation) and assert
    # the real, reachable contract -- a server-side ValidationException on
    # that exact field -- not the documented-but-unreachable
    # WAFConfigurationWarningException (see docstring).
    bad_rule = _header_inspection_rule("bad-header-rule", oversize_handling=None)
    code, message = _error_code(
        lambda: wafv2_novalidate.update_web_acl(
            Name=webacl_name,
            Scope="REGIONAL",
            Id=webacl_id,
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility_config(webacl_name),
            Rules=[bad_rule],
            LockToken=current_lock_token,
        )
    )
    assert code == "ValidationException", (
        "expected a ValidationException naming "
        "'fieldToMatch.headers.oversizeHandling' as null-but-required "
        f"(the real, reachable contract for this precondition); got "
        f"code={code!r} message={message!r}"
    )
    assert message == (
        "1 validation error detected: Value null at "
        "'rules.1.member.statement.byteMatchStatement.fieldToMatch.headers.oversizeHandling' "
        "failed to satisfy constraint: Member must not be null"
    ), message

    unchanged = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    assert [r["Name"] for r in unchanged["WebACL"]["Rules"]] == ["good-header-rule"], (
        f"the rejected UpdateWebACL must not have committed 'bad-header-rule'; "
        f"independent GetWebACL read returned "
        f"{[r['Name'] for r in unchanged['WebACL']['Rules']]!r}"
    )
    assert unchanged["LockToken"] == current_lock_token, (
        f"the rejected UpdateWebACL must not have advanced the LockToken; "
        f"expected {current_lock_token!r}, got {unchanged['LockToken']!r}"
    )


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name.replace(".", ""),
    }


def _client_without_param_validation(ctx):
    """A wafv2 client identical to ctx.client('wafv2') except with client-side
    parameter validation disabled, so a request that boto3 would otherwise
    refuse to serialize locally (a missing shape-required field) is sent to
    the real service instead, letting the *service's* validation respond."""
    return ctx.client("wafv2", config=Config(parameter_validation=False))


def _header_inspection_rule(name: str, oversize_handling: str | None) -> dict:
    headers_field: dict[str, Any] = {
        "MatchPattern": {"All": {}},
        "MatchScope": "ALL",
    }
    if oversize_handling is not None:
        headers_field["OversizeHandling"] = oversize_handling
    return {
        "Name": name,
        "Priority": 0,
        "Action": {"Count": {}},
        "Statement": {
            "ByteMatchStatement": {
                "FieldToMatch": {"Headers": headers_field},
                "PositionalConstraint": "CONTAINS",
                "SearchString": b"attack-signature",
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", ""),
        },
    }


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateWebACL to be rejected for the missing-OversizeHandling "
        f"precondition, but it SUCCEEDED and returned {result!r}"
    )


def _best_effort_delete_webacl(wafv2, name: str, webacl_id: str) -> None:
    try:
        current = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=webacl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise
        return
    try:
        wafv2.delete_web_acl(
            Name=name, Scope="REGIONAL", Id=webacl_id, LockToken=current["LockToken"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
