"""rate-based-statement-window-outside-60-120-300-600-rejected."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "rate-based-statement-window-outside-60-120-300-600-rejected"
GROUP = "rate-based-statement"
SERVICES = ["wafv2"]

_SCOPE = "REGIONAL"
_WINDOWS = (60, 120, 300, 600)


def _visibility(metric: str) -> dict:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}


def _rate_rule(name: str, priority: int, window: int) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"RateBasedStatement": {
            "Limit": 100, "AggregateKeyType": "IP", "EvaluationWindowSec": window,
        }},
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
    """A rate-based rule's EvaluationWindowSec must be one of 60, 120, 300 or 600: an in-range
    value outside that set is rejected by CreateWebACL with WAFInvalidParameterException naming
    the value, creates nothing, and each of the four valid windows round-trips exactly.
    """
    waf = ctx.client("wafv2")
    prefix = ctx.unique_name("sim2real-")

    for bad in (90, 599):
        name = f"{prefix}-bad{bad}"
        got = _error(lambda n=name, b=bad: waf.create_web_acl(
            Name=n, Scope=_SCOPE, DefaultAction={"Allow": {}}, VisibilityConfig=_visibility(n),
            Rules=[_rate_rule("r", 0, b)]))
        want = ("WAFInvalidParameterException",
                f"Error reason: Your request in not valid., field: RATE_BASED_STATEMENT, "
                f"parameter: {bad}")
        assert got == want, f"EvaluationWindowSec={bad} answered {got!r}, expected {want!r}"
    leftover = _names_listed(waf, prefix)
    assert leftover == [], f"rejected creates left WebACLs behind: {leftover!r}"

    name = f"{prefix}-ok"
    rules = [_rate_rule(f"w{w}", i, w) for i, w in enumerate(_WINDOWS)]
    summary = _create_acl(ctx, waf, name, rules)
    acl = waf.get_web_acl(Name=name, Scope=_SCOPE, Id=summary["Id"])["WebACL"]
    stored = {r["Name"]: r["Statement"]["RateBasedStatement"]["EvaluationWindowSec"]
              for r in acl["Rules"]}
    want_stored = {f"w{w}": w for w in _WINDOWS}
    assert stored == want_stored, f"valid windows read back as {stored!r}, expected {want_stored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
