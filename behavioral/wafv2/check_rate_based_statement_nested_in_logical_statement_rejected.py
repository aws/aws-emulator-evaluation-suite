"""rate-based-statement-nested-in-logical-statement-rejected."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "rate-based-statement-nested-in-logical-statement-rejected"
GROUP = "rate-based-statement"
SERVICES = ["wafv2"]

_SCOPE = "REGIONAL"
_RATE_STATEMENT = {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}}
_GEO_STATEMENT = {"GeoMatchStatement": {"CountryCodes": ["US"]}}


def _visibility(metric: str) -> dict:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}


def _rule(statement: dict, name: str) -> dict:
    return {
        "Name": name, "Priority": 0, "Statement": statement, "Action": {"Block": {}},
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
    """A RateBasedStatement nested inside a NotStatement, OrStatement or AndStatement is rejected
    by CreateWebACL with WAFInvalidParameterException and creates nothing; the same
    RateBasedStatement used directly as a rule's own statement, unnested, is accepted.
    """
    waf = ctx.client("wafv2")
    prefix = ctx.unique_name("sim2real-")
    want = ("WAFInvalidParameterException",
            "Error reason: A reference in your rule statement is not valid., "
            "field: RATE_BASED_STATEMENT, parameter: RateBasedStatement")

    nested = {
        "not": {"NotStatement": {"Statement": _RATE_STATEMENT}},
        "or": {"OrStatement": {"Statements": [_RATE_STATEMENT, _GEO_STATEMENT]}},
        "and": {"AndStatement": {"Statements": [_RATE_STATEMENT, _GEO_STATEMENT]}},
    }
    for label, statement in nested.items():
        name = f"{prefix}-{label}"
        got = _error(lambda n=name, s=statement: waf.create_web_acl(
            Name=n, Scope=_SCOPE, DefaultAction={"Allow": {}}, VisibilityConfig=_visibility(n),
            Rules=[_rule(s, "r")]))
        assert got == want, f"RateBasedStatement nested in {label!r} answered {got!r}, expected {want!r}"
    leftover = _names_listed(waf, prefix)
    assert leftover == [], f"rejected creates left WebACLs behind: {leftover!r}"

    ok_name = f"{prefix}-ok"
    summary = _create_acl(ctx, waf, ok_name, [_rule(_RATE_STATEMENT, "r")])
    acl = waf.get_web_acl(Name=ok_name, Scope=_SCOPE, Id=summary["Id"])["WebACL"]
    stored = acl["Rules"][0]["Statement"].get("RateBasedStatement")
    want_stored = dict(_RATE_STATEMENT["RateBasedStatement"], EvaluationWindowSec=300)
    assert stored == want_stored, f"control stored {stored!r}, expected {want_stored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
