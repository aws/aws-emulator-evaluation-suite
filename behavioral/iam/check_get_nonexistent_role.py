"""get-nonexistent-role."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-nonexistent-role"
GROUP = 'errors'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"

_TRUST_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRole succeeds for a role that exists (positive control); the identical
    call for a role that was never created raises NoSuchEntity."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    resp = iam.get_role(RoleName=role_name)
    got_name = resp["Role"]["RoleName"]
    assert got_name == role_name, f"positive control: expected {role_name!r}, got {got_name!r}"

    ghost_name = ctx.unique_name("sim2real-behav-ghost-role-")
    code, message = _error(lambda: iam.get_role(RoleName=ghost_name))
    assert code == ERR_NO_SUCH_ENTITY, f"expected {ERR_NO_SUCH_ENTITY}, got {code!r}"
    expected = f"The role with name {ghost_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
