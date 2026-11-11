"""input-security-group-invalid-cidr-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "input-security-group-invalid-cidr-rejected"
GROUP = "overly-permissive"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInputSecurityGroup rejects a malformed CIDR; a valid CIDR list still creates fine."""
    medialive = ctx.client("medialive")

    code, message = _client_error(
        lambda: medialive.create_input_security_group(WhitelistRules=[{"Cidr": "not-a-cidr"}]),
        "CreateInputSecurityGroup with a malformed CIDR",
    )
    assert code == "BadRequestException", f"expected BadRequestException for a malformed CIDR, got {code!r}"
    assert message == "Every whitelist needs to have a valid IPv4 CIDR.", message
    # Effect absent: no security groups were left behind referencing the bogus rule.
    groups = medialive.list_input_security_groups()["InputSecurityGroups"]
    assert not any(
        any(rule.get("Cidr") == "not-a-cidr" for rule in g.get("WhitelistRules", [])) for g in groups
    ), "a security group referencing the rejected CIDR 'not-a-cidr' leaked into list_input_security_groups"

    # Positive control: a syntactically valid CIDR is accepted.
    group = medialive.create_input_security_group(
        WhitelistRules=[{"Cidr": "10.0.0.0/24"}],
        Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"},
    )["SecurityGroup"]
    group_id = group["Id"]
    ctx.on_cleanup(lambda: medialive.delete_input_security_group(InputSecurityGroupId=group_id))
    assert group["State"] == "IDLE", f"expected IDLE right after create, got {group['State']!r}"

    # Terminal read: an independent DescribeInputSecurityGroup, not the create call's own response.
    described = medialive.describe_input_security_group(InputSecurityGroupId=group_id)
    cidrs = [r["Cidr"] for r in described["WhitelistRules"]]
    assert cidrs == ["10.0.0.0/24"], f"expected the accepted CIDR to round-trip via an independent describe, got {cidrs!r}"
    assert described["State"] == "IDLE", f"expected the accepted group to read IDLE independently, got {described['State']!r}"


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
