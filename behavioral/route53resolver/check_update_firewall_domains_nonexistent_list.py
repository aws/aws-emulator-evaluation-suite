"""update-firewall-domains-nonexistent-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-domains-nonexistent-list"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

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


def _poll(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallDomains on a well-formed but nonexistent FirewallDomainListId is refused
    with ResourceNotFoundException, while the same ADD on a real list succeeds and
    ListFirewallDomains returns the domain.
    """
    r53 = ctx.client("route53resolver")

    name = ctx.unique_name("sim2real-behav-fdl-nonexistent-")
    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=name
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    r53.update_firewall_domains(
        FirewallDomainListId=dl_id, Operation="ADD", Domains=["example.com"]
    )

    def listed_domains():
        return {
            d.lower().rstrip(".")
            for d in r53.list_firewall_domains(FirewallDomainListId=dl_id)["Domains"]
        }

    _poll(
        listed_domains,
        lambda s: s == {"example.com"},
        description="positive control: ListFirewallDomains reflects the ADD",
    )

    missing_id = "rslvr-fdl-00000000000000000"
    refusal = _error(
        lambda: r53.update_firewall_domains(
            FirewallDomainListId=missing_id,
            Operation="ADD",
            Domains=["example.com"],
        )
    )
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-02025] Can\u2019t find the resource with ID "{missing_id}".',
    )
    assert refusal == expected, (
        f"expected {expected!r} for a nonexistent domain list, got {refusal!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
