"""get-firewall-domain-list-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-firewall-domain-list-not-found"
GROUP = 'error-semantics'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFirewallDomainList for a well-formed but nonexistent id is refused with
    ResourceNotFoundException ("[RSLVR-02025] Can't find the resource with ID ..."), while a
    domain list the check creates is returned by the same call.
    """
    r53 = ctx.client("route53resolver")
    bogus_id = ctx.unique_name("sim2real-behav-rslvr-fdl-doesnotexist-")
    code, message = _error(
        lambda: r53.get_firewall_domain_list(FirewallDomainListId=bogus_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{bogus_id}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real domain list must be retrievable.
    name = ctx.unique_name("sim2real-behav-fdl-")
    dl = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"), Name=name
    )["FirewallDomainList"]
    dl_id = dl["Id"]
    ctx.on_cleanup(lambda: r53.delete_firewall_domain_list(FirewallDomainListId=dl_id))

    got = r53.get_firewall_domain_list(FirewallDomainListId=dl_id)["FirewallDomainList"]
    assert got["Id"] == dl_id, f"expected Id {dl_id}, got {got['Id']}"
    assert got["Name"] == name, f"expected Name {name}, got {got['Name']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
