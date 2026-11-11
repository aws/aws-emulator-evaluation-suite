"""list-app-instance-users-reflects-created."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-app-instance-users-reflects-created"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAppInstanceUsers under an AppInstance reflects exactly the users created in it,
    with matching names, and excludes a sibling AppInstance's users."""
    # chime-sdk-identity's control plane is us-east-1 only; every sibling check in this
    # directory pins the same region.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    # A sibling AppInstance with its own user is the twin control: it proves the terminal
    # read is scoped to the AppInstance under test, not to the account as a whole.
    other_instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-other-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=other_instance_arn))
    other_user_arn = client.create_app_instance_user(
        AppInstanceArn=other_instance_arn,
        AppInstanceUserId=ctx.unique_name("other-user-"),
        Name="other-member",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    expected = {}
    for i in range(3):
        uid = ctx.unique_name(f"user-{i}-")
        name = f"member-{i}"
        arn = client.create_app_instance_user(
            AppInstanceArn=instance_arn,
            AppInstanceUserId=uid,
            Name=name,
            ClientRequestToken=uuid.uuid4().hex,
        )["AppInstanceUserArn"]
        expected[arn] = name

    users = []
    next_token = None
    while True:
        kwargs = {"AppInstanceArn": instance_arn, "MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token
        page = client.list_app_instance_users(**kwargs)
        users.extend(page["AppInstanceUsers"])
        next_token = page.get("NextToken")
        if not next_token:
            break

    found = {u["AppInstanceUserArn"]: u["Name"] for u in users}
    assert set(found) == set(expected), (
        f"ListAppInstanceUsers under {instance_arn!r} returned {set(found)!r}, "
        f"expected exactly {set(expected)!r}"
    )
    for arn, name in expected.items():
        assert found.get(arn) == name, (
            f"AppInstanceUser {arn!r} listed with Name {found.get(arn)!r}, expected {name!r}"
        )
    assert other_user_arn not in found, (
        f"sibling AppInstance's user {other_user_arn!r} leaked into "
        f"{instance_arn!r}'s ListAppInstanceUsers result {set(found)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
