"""duplicate-role-name-across-regional-clients-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-role-name-across-regional-clients-rejected"
GROUP = "global-service-regional-endpoints"
SERVICES = ["iam"]

_TRUST_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
)

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role name created through one regional IAM client collides when a second regional client
    creates the same name: IAM has one global namespace, not one per endpoint."""
    # IAM is a global service: a second literal region is the subject, not an environment pin.
    other_region = "eu-west-1" if ctx.region != "eu-west-1" else "us-west-2"
    owner = ctx.client("iam", region=ctx.region)
    other = ctx.client("iam", region=other_region)

    role_name = ctx.unique_name("sim2real-dupe-role-")
    first = owner.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY,
                              Tags=_TAGS)["Role"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: owner.delete_role(RoleName=role_name)))

    try:
        other.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY, Tags=_TAGS)
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(
            f"creating {role_name!r} again through {other_region} SUCCEEDED; the name must be "
            "reserved globally, not per regional endpoint"
        )
    assert code == "EntityAlreadyExists", (
        f"creating {role_name!r} again through {other_region} returned {code!r}, expected "
        "EntityAlreadyExists -- the name must be reserved globally, not per regional endpoint"
    )
    expected = f"Role with name {role_name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: exactly one role exists under this name, with the FIRST call's identity.
    role = owner.get_role(RoleName=role_name)["Role"]
    assert role["RoleId"] == first["RoleId"], (
        f"the original role must be unaffected: RoleId {first['RoleId']!r} -> {role['RoleId']!r}"
    )

    # Positive control, same file: a genuinely new name through the SECOND region succeeds,
    # proving the rejection above was about the name colliding, not about `other` being broken.
    control_name = ctx.unique_name("sim2real-dupe-role-control-")
    created = other.create_role(RoleName=control_name, AssumeRolePolicyDocument=_TRUST_POLICY,
                                Tags=_TAGS)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: other.delete_role(RoleName=control_name)))
    assert created["Role"]["RoleName"] == control_name, (
        f"control CreateRole through {other_region} returned RoleName "
        f"{created['Role']['RoleName']!r}, expected {control_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
