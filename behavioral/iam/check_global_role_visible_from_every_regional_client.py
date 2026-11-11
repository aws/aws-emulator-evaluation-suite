"""global-role-visible-from-every-regional-client."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-role-visible-from-every-regional-client"
GROUP = "global-service-regional-endpoints"
SERVICES = ["iam"]


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("call unexpectedly succeeded where a NoSuchEntity error was expected")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IAM is global: a role created via one regional client reads identically via a second, is
    deleted via a third, and the deletion is visible through the first two."""
    # Reader and deleter use fixed regions, each swapped for us-east-2 when it is the run's own.
    create_region = ctx.region
    read_region, delete_region = (
        "us-west-2" if ctx.region != "us-west-2" else "us-east-2",
        "eu-west-1" if ctx.region != "eu-west-1" else "us-east-2",
    )
    assert create_region not in (read_region, delete_region), (
        f"creator region {create_region!r} collided with a literal probe region; "
        "cross-endpoint visibility would be untested"
    )

    creator = ctx.client("iam", region=create_region)
    reader = ctx.client("iam", region=read_region)
    deleter = ctx.client("iam", region=delete_region)

    role_name = ctx.unique_name("sim2real-xregion-role-")
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    created = creator.create_role(
        RoleName=role_name, Path="/sim2real/", AssumeRolePolicyDocument=trust_policy,
        Description="sim2real cross-region visibility probe",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: creator.delete_role(RoleName=role_name)))

    seen = reader.get_role(RoleName=role_name)["Role"]
    assert seen["Arn"] == created["Arn"], (
        f"role read back through {read_region} has Arn {seen['Arn']!r}, "
        f"expected the one {create_region} created: {created['Arn']!r}"
    )
    assert seen["RoleId"] == created["RoleId"], (
        f"RoleId differs across regional clients: {seen['RoleId']!r} vs {created['RoleId']!r}"
    )
    assert seen["Path"] == "/sim2real/", f"Path read back through {read_region} was {seen['Path']!r}"
    assert seen["CreateDate"] == created["CreateDate"], (
        f"CreateDate differs across regional clients: {seen['CreateDate']!r} vs "
        f"{created['CreateDate']!r} -- two different stores, not one global resource"
    )

    deleter.delete_role(RoleName=role_name)

    expected = f"The role with name {role_name} cannot be found."
    code, message = _error(lambda: creator.get_role(RoleName=role_name))
    assert code == "NoSuchEntity", (
        f"deleting through {delete_region} left the role visible through {create_region} "
        f"(get_role raised {code!r} instead of NoSuchEntity) -- the delete did not propagate "
        "to every regional endpoint of the one global store"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code, message = _error(lambda: reader.get_role(RoleName=role_name))
    assert code == "NoSuchEntity", (
        f"deleting through {delete_region} left the role visible through {read_region} "
        f"(get_role raised {code!r} instead of NoSuchEntity)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
