"""op-contract-acquireRole."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-acquireRole"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcquireRole with a TemplateArn that names no role template fails with NoSuchEntity and its
    exact message, and no role named after the template exists afterwards; ListRoles succeeds
    first."""
    iam = ctx.client("iam")

    positive_control = iam.list_roles(MaxItems=1)
    assert "Roles" in positive_control, (
        f"expected IAM to be reachable and healthy for this session, got {positive_control!r}"
    )

    bogus_name = ctx.unique_name("sim2real-tmpl-")
    template_arn = f"arn:aws:iam::aws:role-template/{bogus_name}:1"

    # IAM is a query-protocol service: the wire-level Error.Code omits the "Exception"
    # suffix that appears in the operation's documented exception shape name (e.g. the
    # shape "NoSuchEntityException" is returned on the wire as Code "NoSuchEntity").
    code, message = _error(lambda: iam.acquire_role(TemplateArn=template_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Role template not found: {template_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The role that a successful AcquireRole would have derived from this (nonexistent)
    # template's basename must not exist in the account.
    role_code, role_message = _error(lambda: iam.get_role(RoleName=bogus_name))
    assert role_code == "NoSuchEntity", (
        f"no role should have been created from a rejected template acquisition, got {role_code}"
    )
    expected = f"The role with name {bogus_name} cannot be found."
    assert role_message == expected, f"expected message {expected!r}, got {role_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
