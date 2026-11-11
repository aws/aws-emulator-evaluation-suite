"""subnet-group-update-replaces-subnet-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-update-replaces-subnet-set"
GROUP = 'subnet-groups'
SERVICES = ['memorydb']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _drop_sg(m, name: str) -> None:
    try:
        m.delete_subnet_group(SubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "SubnetGroupNotFoundFault":
            raise


def _layout(group: dict) -> dict:
    return {s["Identifier"]: s["AvailabilityZone"]["Name"] for s in group["Subnets"]}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSubnetGroup replaces a subnet group's subnets: widening to every subnet and narrowing to one
    both read back exactly, each subnet in its own zone; duplicate ids collapse; an invalid id and an
    empty update are refused without changing the set.
    """
    m = ctx.client("memorydb")
    net = ctx.network()
    subnets = net.subnet_ids
    assert len(subnets) >= 2, f"the run's network has {len(subnets)} subnet(s), need two"
    want = {sid: az for az, sid in net.subnets.items()}
    name = ctx.unique_name("sim2real-mdb-")

    created = m.create_subnet_group(SubnetGroupName=name, SubnetIds=[subnets[0], subnets[0]],
                                    Tags=[{"Key": "sim2real", "Value": CHECK}])["SubnetGroup"]
    ctx.on_cleanup(lambda: _drop_sg(m, name))
    assert _layout(created) == {subnets[0]: want[subnets[0]]}, f"duplicate ids gave {created['Subnets']!r}"
    assert created["VpcId"] == net.vpc_id, "subnet group is not in the subnets' VPC"
    assert "Description" not in created, f"an omitted description reads back as {created.get('Description')!r}"
    assert created["SupportedNetworkTypes"] == ["ipv4"], f"network types {created['SupportedNetworkTypes']!r}"

    m.update_subnet_group(SubnetGroupName=name, SubnetIds=subnets)
    wide = m.describe_subnet_groups(SubnetGroupName=name)["SubnetGroups"][0]
    assert _layout(wide) == want, f"widening read back {_layout(wide)!r}"

    m.update_subnet_group(SubnetGroupName=name, SubnetIds=[subnets[1]])
    narrow = m.describe_subnet_groups(SubnetGroupName=name)["SubnetGroups"][0]
    assert _layout(narrow) == {subnets[1]: want[subnets[1]]}, f"narrowing read back {_layout(narrow)!r}"

    fake = "subnet-0123456789abcdef0"
    code, msg = _error(lambda: m.update_subnet_group(SubnetGroupName=name, SubnetIds=[fake]))
    assert code == "InvalidParameterValueException", f"an unknown subnet gave {code}: {msg!r}"
    assert msg == f"The provided input subnet ids are invalid : [{fake}].", f"message was {msg!r}"
    code, msg = _error(lambda: m.update_subnet_group(SubnetGroupName=name))
    assert (code, msg) == ("InvalidParameterValueException", "No modifications were requested."), (
        f"an empty update gave {code}: {msg!r}"
    )
    after = m.describe_subnet_groups(SubnetGroupName=name)["SubnetGroups"][0]
    assert _layout(after) == {subnets[1]: want[subnets[1]]}, f"a refused update changed the set to {_layout(after)!r}"

    m.update_subnet_group(SubnetGroupName=name, Description="sim2real described")
    described = m.describe_subnet_groups(SubnetGroupName=name)["SubnetGroups"][0]
    assert described["Description"] == "sim2real described", f"description {described.get('Description')!r}"
    assert _layout(described) == {subnets[1]: want[subnets[1]]}, "a description update changed the subnets"

    m.delete_subnet_group(SubnetGroupName=name)
    code, msg = _error(lambda: m.describe_subnet_groups(SubnetGroupName=name))
    assert code == "SubnetGroupNotFoundFault", f"a deleted group read gave {code}: {msg!r}"
    assert msg == f"Subnet group {name} not found.", f"message was {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
