"""list-resolver-configs-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resolver-configs-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResolverConfigs rejects both garbage text and a real token from ListFirewallDomainLists as
    a NextToken with InvalidParameterException, while a call without a NextToken succeeds.
    """
    r53r = ctx.client("route53resolver")

    garbage_code, garbage_message = _error(
        lambda: r53r.list_resolver_configs(NextToken="not-a-real-next-token-!!!")
    )
    assert garbage_code == "InvalidParameterException", (
        f"expected InvalidParameterException for garbage NextToken, got {garbage_code}"
    )
    expected = "Value ( not-a-real-next-token-!!! ) for parameter NextToken is invalid. The token is invalid."
    assert garbage_message == expected, f"expected message {expected!r}, got {garbage_message!r}"

    # Two domain lists guarantee ListFirewallDomainLists(MaxResults=1) returns a NextToken.
    # Unlike ListResolverEndpoints, this foreign token gets InvalidParameterException, not
    # InvalidNextTokenException.
    created_ids = []
    for _ in range(2):
        dl = r53r.create_firewall_domain_list(
            CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
            Name=ctx.unique_name("sim2real-behav-fdl-"),
            Tags=TAGS_KV,
        )["FirewallDomainList"]
        dl_id = dl["Id"]
        ctx.on_cleanup(lambda i=dl_id: r53r.delete_firewall_domain_list(FirewallDomainListId=i))
        created_ids.append(dl_id)

    donor = r53r.list_firewall_domain_lists(MaxResults=1)

    foreign_token = donor.get("NextToken")
    assert foreign_token, "expected the donor List call to be truncated and return a NextToken"

    foreign_code, foreign_message = _error(lambda: r53r.list_resolver_configs(NextToken=foreign_token))
    assert foreign_code == "InvalidParameterException", (
        f"expected InvalidParameterException for foreign NextToken, got {foreign_code}"
    )
    expected = f"Value ( {foreign_token} ) for parameter NextToken is invalid. The token is invalid."
    assert foreign_message == expected, f"expected message {expected!r}, got {foreign_message!r}"

    resp = r53r.list_resolver_configs(MaxResults=5)
    assert "ResolverConfigs" in resp, f"expected ResolverConfigs in response, got keys {list(resp)}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


