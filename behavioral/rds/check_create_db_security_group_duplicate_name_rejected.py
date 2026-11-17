"""create-db-security-group-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-db-security-group-duplicate-name-rejected"
GROUP = "security_groups"
SERVICES = ["rds"]

ERR_ALREADY_EXISTS = "DBSecurityGroupAlreadyExists"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBSecurityGroup with a name that already exists is rejected with
    DBSecurityGroupAlreadyExists, and the existing group's description is unchanged."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-secg-")
    first_description = "sim2real original description"
    rds.create_db_security_group(DBSecurityGroupName=name, DBSecurityGroupDescription=first_description)
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=name))

    code, message = _error_code(
        lambda: rds.create_db_security_group(
            DBSecurityGroupName=name, DBSecurityGroupDescription="sim2real duplicate attempt"
        )
    )
    assert code == ERR_ALREADY_EXISTS, f"unexpected error code: {code!r}"
    expected = f"A security group named {name} already exists"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    described = rds.describe_db_security_groups(DBSecurityGroupName=name)["DBSecurityGroups"]
    assert len(described) == 1, f"expected exactly one group named {name!r}, got {described!r}"
    assert described[0]["DBSecurityGroupDescription"] == first_description, (
        f"the rejected duplicate create must not alter the existing group's description, "
        f"got {described[0]['DBSecurityGroupDescription']!r}"
    )

    # Positive control: an unrelated name is still creatable.
    other_name = ctx.unique_name("sim2real-behav-secg-other-")
    rds.create_db_security_group(
        DBSecurityGroupName=other_name, DBSecurityGroupDescription="sim2real positive control"
    )
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=other_name))
    other_described = rds.describe_db_security_groups(DBSecurityGroupName=other_name)["DBSecurityGroups"]
    assert len(other_described) == 1 and other_described[0]["DBSecurityGroupName"] == other_name, (
        f"positive control group not independently readable: {other_described!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
