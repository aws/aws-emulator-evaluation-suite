"""create-firewall-rule-group-all-digit-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-group-all-digit-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_when_possible(fn, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """Retry a delete until it succeeds or the resource is gone; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "ResourceNotFoundException":
                return
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"teardown {fn.__name__}({kwargs}) never succeeded; last error {last}")


def _all_rule_group_names(r53):
    """Return every firewall rule group name in the account, following pagination."""
    names = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_firewall_rule_groups(**kwargs)
        names.extend(g.get("Name") for g in page.get("FirewallRuleGroups", []))
        token = page.get("NextToken")
        if not token:
            return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An all-numeric firewall rule group Name is refused while an alphanumeric one is accepted,
    because the modeled Name pattern's negative lookahead keeps names distinguishable from ids.
    botocore does not enforce `pattern`, so the constraint is purely server-side.
    """
    r53 = ctx.client("route53resolver")

    good_name = ctx.unique_name("sim2real-behav-frg-")
    good = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=good_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["FirewallRuleGroup"]
    ctx.on_cleanup(
        lambda x=good["Id"]: _delete_when_possible(
            r53.delete_firewall_rule_group, FirewallRuleGroupId=x
        )
    )
    assert good["Name"] == good_name, good
    assert good["Status"] in ("COMPLETE", "UPDATING"), good

    # An all-digit name cannot carry the usual prefix; the call is expected to create nothing.
    bad_name = str(time.time_ns())[-14:]
    assert bad_name.isdigit(), bad_name
    err = _client_error(
        lambda: r53.create_firewall_rule_group(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            Name=bad_name,
        )
    )
    assert err["Code"] == "ValidationException", (
        f"expected ValidationException for all-digit rule group Name {bad_name!r}, got {err}"
    )
    assert err["Message"] == (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "(?!^[0-9]+$)([a-zA-Z0-9\\-_' ']+)"
    ), err

    # Scoped by name rather than set equality: ListFirewallRuleGroups is account-wide.
    names = _all_rule_group_names(r53)
    assert bad_name not in names, (
        f"a rejected all-digit rule group must not be stored; account holds {len(names)} groups "
        f"including {bad_name!r}"
    )

    assert good_name in names, f"control group {good_name!r} missing from {len(names)} listed"
    reread = r53.get_firewall_rule_group(FirewallRuleGroupId=good["Id"])["FirewallRuleGroup"]
    assert reread["Name"] == good_name, reread


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
