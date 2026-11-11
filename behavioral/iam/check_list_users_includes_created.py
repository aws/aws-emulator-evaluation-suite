"""list-users-includes-created."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-users-includes-created"
GROUP = 'user_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers includes a user we just created, with matching representation."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-user-")
    created = iam.create_user(UserName=name, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]
    ctx.on_cleanup(lambda n=name: iam.delete_user(UserName=n))
    paginator = iam.get_paginator("list_users")
    found = None
    for page in paginator.paginate():
        for user in page["Users"]:
            if user["UserName"] == name:
                found = user
                break
        if found:
            break
    assert found is not None, f"User {name} not found in ListUsers"
    assert found["Arn"] == created["Arn"], f"Arn mismatch: {found['Arn']} != {created['Arn']}"
    assert found["UserId"] == created["UserId"], f"UserId mismatch: {found['UserId']} != {created['UserId']}"
    assert found["Path"] == "/", f"expected Path '/', got {found['Path']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
