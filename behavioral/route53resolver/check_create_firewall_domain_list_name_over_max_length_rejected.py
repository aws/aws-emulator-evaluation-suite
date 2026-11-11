"""create-firewall-domain-list-name-over-max-length-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-domain-list-name-over-max-length-rejected"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

NAME_MAX = 64  # com.amazonaws.route53resolver#Name @length(min:0, max:64)


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
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


def _all_domain_list_names(r53):
    """Return every firewall domain list name in the account, following pagination."""
    names = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_firewall_domain_lists(**kwargs)
        names.extend(dl.get("Name") for dl in page.get("FirewallDomainLists", []))
        token = page.get("NextToken")
        if not token:
            return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A firewall domain list Name of 65 chars is refused; exactly 64 is accepted verbatim.
    The boundary pair catches truncation instead of refusal, which would silently change the
    identifier later name lookups depend on."""
    r53 = ctx.client("route53resolver")

    # CONTROL: exactly at the ceiling must be ACCEPTED and stored verbatim, untruncated.
    at_limit = (ctx.unique_name("sim2real-behav-fdl-") + "-pad-" + "a" * NAME_MAX)[:NAME_MAX]
    assert len(at_limit) == NAME_MAX, at_limit
    good = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=at_limit,
    )["FirewallDomainList"]
    ctx.on_cleanup(
        lambda x=good["Id"]: _delete_when_possible(
            r53.delete_firewall_domain_list, FirewallDomainListId=x
        )
    )
    assert good["Name"] == at_limit, (
        f"a name at the {NAME_MAX}-char ceiling must be stored verbatim, got {good['Name']!r}"
    )

    # One character over the ceiling. botocore checks only the min length, so the
    # over-long name reaches the service and the max is enforced server-side.
    over_limit = at_limit + "z"
    assert len(over_limit) == NAME_MAX + 1, over_limit
    err = _client_error(
        lambda: r53.create_firewall_domain_list(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            Name=over_limit,
        )
    )
    assert err["Code"] == "ValidationException", (
        f"expected ValidationException for a {len(over_limit)}-char Name "
        f"(ceiling {NAME_MAX}), got {err}"
    )
    assert err["Message"] == (
        f"1 validation error detected: Value '{over_limit}' at 'name' failed to satisfy "
        f"constraint: Member must have length less than or equal to {NAME_MAX}"
    ), err

    # EFFECT ABSENT, and specifically NOT truncated: neither the over-long name nor a
    # truncation of it may appear as a second list.
    names = _all_domain_list_names(r53)
    assert over_limit not in names, (
        f"a rejected over-long name must not be stored; account holds {len(names)} lists"
    )
    assert names.count(at_limit) == 1, (
        f"the over-long name must not have been truncated into a second list named "
        f"{at_limit!r}; found {names.count(at_limit)} occurrences"
    )

    # CONTROL STILL WORKS: the at-limit list is readable and unchanged.
    reread = r53.get_firewall_domain_list(FirewallDomainListId=good["Id"])[
        "FirewallDomainList"
    ]
    assert reread["Name"] == at_limit, reread
    assert reread.get("DomainCount", 0) == 0, (
        f"an untouched domain list must hold no domains, got {reread!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
