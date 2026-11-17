"""modify-db-subnet-group-replaces-membership-and-az-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-db-subnet-group-replaces-membership-and-az-boundary"
GROUP = "subnet_groups"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBSubnetGroup replaces the member subnets outright rather than adding to them, and a
    modify that would leave fewer than two AZs is rejected with the membership left untouched.
    """
    rds = ctx.client("rds")
    net = ctx.network()
    azs = sorted(net.subnets)
    if len(azs) < 3:
        raise AssertionError(
            f"the shared network only spans {azs!r}; at least 3 availability zones are "
            "needed to prove a modify replaces membership rather than unions it"
        )
    az_a, az_b, az_c = azs[0], azs[1], azs[2]
    subnet_a, subnet_b, subnet_c = net.subnets[az_a], net.subnets[az_b], net.subnets[az_c]

    name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=[subnet_a, subnet_b],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))

    created = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"][0]
    assert {s["SubnetIdentifier"] for s in created["Subnets"]} == {subnet_a, subnet_b}, (
        f"expected members {{subnet_a, subnet_b}}, got {created['Subnets']!r}"
    )

    # A full replacement, not a union: dropping subnet_b and adding subnet_c leaves exactly
    # {subnet_a, subnet_c} -- subnet_b must not remain a member.
    rds.modify_db_subnet_group(DBSubnetGroupName=name, SubnetIds=[subnet_a, subnet_c])
    replaced = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"][0]
    assert {s["SubnetIdentifier"] for s in replaced["Subnets"]} == {subnet_a, subnet_c}, (
        f"expected the modify to replace membership with {{subnet_a, subnet_c}}, "
        f"got {replaced['Subnets']!r}"
    )
    assert replaced["SubnetGroupStatus"] == "Complete", (
        f"expected SubnetGroupStatus Complete after modify, got {replaced['SubnetGroupStatus']!r}"
    )

    # Boundary: a modify down to a single AZ is rejected, and membership stays at the two
    # subnets the prior successful modify left in place.
    code, message = _error(lambda: rds.modify_db_subnet_group(DBSubnetGroupName=name, SubnetIds=[subnet_a]))
    assert code == "DBSubnetGroupDoesNotCoverEnoughAZs", (
        f"expected DBSubnetGroupDoesNotCoverEnoughAZs modifying down to one AZ, got {code!r}: {message!r}"
    )
    assert message == (
        "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
        f"Current AZ coverage: {az_a}. Add subnets to cover at least 2 AZs."
    ), f"unexpected message for the single-AZ rejection: {message!r}"

    unchanged = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"][0]
    assert {s["SubnetIdentifier"] for s in unchanged["Subnets"]} == {subnet_a, subnet_c}, (
        f"the rejected modify must leave membership at {{subnet_a, subnet_c}}, "
        f"got {unchanged['Subnets']!r}"
    )

    # Restore: the identical group accepts a further valid modify right after the rejection.
    rds.modify_db_subnet_group(DBSubnetGroupName=name, SubnetIds=[subnet_b, subnet_c])
    restored = rds.describe_db_subnet_groups(DBSubnetGroupName=name)["DBSubnetGroups"][0]
    assert {s["SubnetIdentifier"] for s in restored["Subnets"]} == {subnet_b, subnet_c}, (
        f"expected the follow-up modify to succeed with {{subnet_b, subnet_c}}, "
        f"got {restored['Subnets']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
