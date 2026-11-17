"""rate-based-statement-constant-key-without-scope-down-rejected."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "rate-based-statement-constant-key-without-scope-down-rejected"
GROUP = "rate-based-statement"
SERVICES = ["wafv2"]

_SCOPE = "REGIONAL"
_SCOPE_DOWN = {"ByteMatchStatement": {
    "SearchString": b"/login", "FieldToMatch": {"UriPath": {}},
    "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
    "PositionalConstraint": "STARTS_WITH",
}}


def _visibility(metric: str) -> dict:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}


def _rate_rule(name: str, **statement_extra) -> dict:
    statement = {"Limit": 100, "AggregateKeyType": "CONSTANT"}
    statement.update(statement_extra)
    return {
        "Name": name,
        "Priority": 0,
        "Statement": {"RateBasedStatement": statement},
        "Action": {"Block": {}},
        "VisibilityConfig": _visibility(name),
    }


def _create_acl(ctx, waf, name: str, rules: list) -> dict:
    """CreateWebACL in REGIONAL scope; the delete is registered before anything else can fail."""
    summary = waf.create_web_acl(
        Name=name, Scope=_SCOPE, DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility(name), Rules=rules,
    )["Summary"]
    ctx.on_cleanup(_teardown(waf, name, summary["Id"]))
    return summary


def _teardown(waf, name: str, acl_id: str):
    def undo() -> None:
        from botocore.exceptions import ClientError

        for _ in range(5):
            try:
                token = waf.get_web_acl(Name=name, Scope=_SCOPE, Id=acl_id)["LockToken"]
                waf.delete_web_acl(Name=name, Scope=_SCOPE, Id=acl_id, LockToken=token)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "WAFNonexistentItemException":
                    return
                if code != "WAFOptimisticLockException":
                    raise
        raise RuntimeError(f"WebACL {name} ({acl_id}) kept losing the lock race; not deleted")

    return undo


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn() raises. Raises if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _names_listed(waf, prefix: str) -> list[str]:
    """Every REGIONAL WebACL name under prefix, paginated: the account is shared with concurrent runs."""
    names: list[str] = []
    kwargs = {"Scope": _SCOPE, "Limit": 100}
    while True:
        resp = waf.list_web_acls(**kwargs)
        names.extend(a["Name"] for a in resp.get("WebACLs") or [] if a["Name"].startswith(prefix))
        marker = resp.get("NextMarker")
        if not marker:
            return sorted(names)
        kwargs["NextMarker"] = marker


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A rate-based rule's AggregateKeyType CONSTANT requires a ScopeDownStatement: without one,
    CreateWebACL rejects it with WAFInvalidParameterException and creates nothing; with one, it
    reads back as CONSTANT with the scope-down statement intact and no CustomKeys populated.
    """
    waf = ctx.client("wafv2")
    prefix = ctx.unique_name("sim2real-")

    bad_name = f"{prefix}-bad"
    got = _error(lambda: waf.create_web_acl(
        Name=bad_name, Scope=_SCOPE, DefaultAction={"Allow": {}}, VisibilityConfig=_visibility(bad_name),
        Rules=[_rate_rule("r")]))
    want = ("WAFInvalidParameterException",
            "Error reason: A required field is missing from the parameter., "
            "field: SCOPE_DOWN, parameter: RateBasedStatement")
    assert got == want, f"CONSTANT without ScopeDownStatement answered {got!r}, expected {want!r}"
    leftover = _names_listed(waf, prefix)
    assert leftover == [], f"the rejected create left WebACLs behind: {leftover!r}"

    ok_name = f"{prefix}-ok"
    summary = _create_acl(ctx, waf, ok_name, [_rate_rule("r", ScopeDownStatement=_SCOPE_DOWN)])
    acl = waf.get_web_acl(Name=ok_name, Scope=_SCOPE, Id=summary["Id"])["WebACL"]
    stored = acl["Rules"][0]["Statement"]["RateBasedStatement"]
    assert stored.get("AggregateKeyType") == "CONSTANT", f"control stored {stored!r}"
    assert stored.get("ScopeDownStatement") == _SCOPE_DOWN, f"control stored {stored!r}"
    for absent in ("CustomKeys", "ForwardedIPConfig"):
        assert absent not in stored, f"{absent} was never declared but reads back as {stored[absent]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
