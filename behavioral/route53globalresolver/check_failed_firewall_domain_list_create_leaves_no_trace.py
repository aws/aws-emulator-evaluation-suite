"""failed-firewall-domain-list-create-leaves-no-trace."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-firewall-domain-list-create-leaves-no-trace"
GROUP = "firewall-domain-lists"
SERVICES = ["route53globalresolver"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _all_firewall_domain_list_names(client) -> set[str]:
    names = set()
    for page in client.get_paginator("list_firewall_domain_lists").paginate():
        names.update(fdl["name"] for fdl in page["firewallDomainLists"])
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFirewallDomainList under a nonexistent GlobalResolver is rejected, and the
    rejected name never shows up in the account-wide listing a successful create would join."""
    client = ctx.client("route53globalresolver", region="us-east-2")
    missing_resolver_id = ctx.unique_name("sim2real-behav-rslvr-missing-")
    fdl_name = ctx.unique_name("sim2real-behav-fdl-")
    client_token = ctx.unique_name("sim2real-behav-tok-")

    # Positive control: the read path itself works before we exercise the failed create.
    baseline_names = _all_firewall_domain_list_names(client)
    assert fdl_name not in baseline_names, (
        f"generated name {fdl_name!r} was already present before the create was even attempted"
    )

    code, message = _error(
        lambda: client.create_firewall_domain_list(
            globalResolverId=missing_resolver_id, name=fdl_name, clientToken=client_token
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"[GR-ERR00309] No GlobalResolver found with the ID: {missing_resolver_id}", (
        f"unexpected message {message!r}"
    )

    after_names = _all_firewall_domain_list_names(client)
    assert fdl_name not in after_names, (
        f"the rejected create's name {fdl_name!r} appeared in the account-wide listing anyway: "
        f"{sorted(n for n in after_names if n not in baseline_names)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
