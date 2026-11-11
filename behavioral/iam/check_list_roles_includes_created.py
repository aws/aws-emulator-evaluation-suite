"""list-roles-includes-created."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

CHECK = "list-roles-includes-created"
GROUP = 'role_lifecycle'
SERVICES = ['iam']


def _in_list_roles(iam, name: str) -> bool:
    paginator = iam.get_paginator("list_roles")
    return any(
        role["RoleName"] == name for page in paginator.paginate() for role in page["Roles"]
    )


def _error_code(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRoles includes a role we just created, and stops including it once deleted."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: _gone_ok(lambda: iam.delete_role(RoleName=n)))

    assert _in_list_roles(iam, name), f"Role {name} not found in ListRoles after creation"

    iam.delete_role(RoleName=name)
    code, message = _error_code(lambda: iam.get_role(RoleName=name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for deleted role {name}, got {code}"
    expected_message = f"The role with name {name} cannot be found."
    assert message == expected_message, (
        f"GetRole on the deleted role must carry AWS's exact message {expected_message!r}; "
        f"got {message!r}"
    )
    assert not _in_list_roles(iam, name), f"Role {name} still present in ListRoles after delete"


def _gone_ok(fn):
    """Teardown-only: the body deletes this resource itself, so tolerate it already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
