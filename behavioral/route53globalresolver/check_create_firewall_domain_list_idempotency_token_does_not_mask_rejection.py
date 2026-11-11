"""create-firewall-domain-list-idempotency-token-does-not-mask-rejection."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-domain-list-idempotency-token-does-not-mask-rejection"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying CreateFirewallDomainList with the same clientToken re-validates the
    request instead of returning a cached answer for a call that never succeeded."""
    client = ctx.client("route53globalresolver", region="us-east-2")
    missing_resolver_id = ctx.unique_name("sim2real-behav-rslvr-missing-")
    fdl_name = ctx.unique_name("sim2real-behav-fdl-")
    client_token = ctx.unique_name("sim2real-behav-tok-")

    def attempt():
        return client.create_firewall_domain_list(
            globalResolverId=missing_resolver_id, name=fdl_name, clientToken=client_token
        )

    expected_message = f"[GR-ERR00309] No GlobalResolver found with the ID: {missing_resolver_id}"

    first_code, first_message = _error(attempt)
    assert first_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on the first call, got {first_code}: {first_message!r}"
    )
    assert first_message == expected_message, f"unexpected first message {first_message!r}"

    second_code, second_message = _error(attempt)
    assert second_code == "ResourceNotFoundException", (
        f"idempotency token masked the rejection on replay: got {second_code}: {second_message!r}"
    )
    assert second_message == expected_message, (
        f"replay under the same clientToken answered a different message than the original "
        f"rejection: {second_message!r} vs {expected_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
