"""unicode-resolver-rule-name-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unicode-resolver-rule-name-round-trip"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResolverRule with a raw non-ASCII DomainName is refused with InvalidParameterException
    ("[RSLVR-00711] Invalid domain or delegation record") and creates nothing, while the punycode
    spelling is accepted and returned by GetResolverRule and ListResolverRules.
    """
    r53r = ctx.client("route53resolver")

    unique = ctx.unique_name("sim2real-r53r-")
    # "m\u00fcnchen" \u2014 a real IDN label with a diacritic outside ASCII.
    ace_domain = f"xn--mnchen-3ya.{unique}.example."
    raw_unicode_domain = f"m\u00fcnchen.{unique}.example."

    # Positive control: the account and credentials are otherwise healthy for
    # CreateResolverRule, and the ACE spelling of an internationalized domain is accepted.
    created = r53r.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crr-"),
        Name=ctx.unique_name("sim2real-rule-")[:64],
        RuleType="SYSTEM",
        DomainName=ace_domain,
    )["ResolverRule"]
    rule_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule(r53r, rule_id))

    assert created["DomainName"].rstrip(".").lower() == ace_domain.rstrip(".").lower(), (
        f"ACE-encoded domain round-trip mismatch on create: "
        f"{created['DomainName']!r} != {ace_domain!r}"
    )

    fetched = r53r.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert fetched["DomainName"] == created["DomainName"], (
        f"GetResolverRule projected {fetched['DomainName']!r}, "
        f"Create projected {created['DomainName']!r}"
    )

    # The identical label spelled with raw unicode bytes is refused, not stored.
    def create_raw():
        rule = r53r.create_resolver_rule(
            CreatorRequestId=ctx.unique_name("sim2real-r53r-crr2-"),
            Name=ctx.unique_name("sim2real-rule2-")[:64],
            RuleType="SYSTEM",
            DomainName=raw_unicode_domain,
        )["ResolverRule"]
        ctx.on_cleanup(lambda x=rule["Id"]: _safe_delete_rule(r53r, x))
        return rule

    refusal = _error(create_raw)
    expected = ("InvalidParameterException", "[RSLVR-00711] Invalid domain or delegation record")
    assert refusal == expected, (
        f"expected {expected!r} for a raw-unicode DomainName {raw_unicode_domain!r}, got {refusal!r}"
    )

    # Effect-absent: the rejected domain was never created, at the destination.
    listed_domains = {r["DomainName"].rstrip(".").lower() for r in _list_all_rules(r53r)}
    assert raw_unicode_domain.rstrip(".").lower() not in listed_domains, (
        f"a rejected CreateResolverRule call must leave no rule for "
        f"{raw_unicode_domain!r} in ListResolverRules"
    )


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _list_all_rules(r53r):
    token = None
    rules = []
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53r.list_resolver_rules(**kwargs)
        rules.extend(page.get("ResolverRules", []))
        token = page.get("NextToken")
        if not token:
            return rules


def _safe_delete_rule(r53r, rule_id):
    try:
        r53r.delete_resolver_rule(ResolverRuleId=rule_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
