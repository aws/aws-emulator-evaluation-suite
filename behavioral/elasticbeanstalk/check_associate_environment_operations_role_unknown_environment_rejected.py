"""associate-environment-operations-role-unknown-environment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-environment-operations-role-unknown-environment-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateEnvironmentOperationsRole with a never-created EnvironmentName fails with
    InvalidParameterValue "No Environment found for EnvironmentName = '<name>'." before the role is evaluated,
    and no environment of that name exists."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-ebops-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"elasticbeanstalk.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    bogus_env_name = ctx.unique_name("sim2real-eb-ghost-")
    code, message = _error_code(
        lambda: eb.associate_environment_operations_role(EnvironmentName=bogus_env_name, OperationsRole=role_arn)
    )
    assert code == "InvalidParameterValue", f"unexpected error code for a nonexistent environment: {code}"
    assert message == f"No Environment found for EnvironmentName = '{bogus_env_name}'.", message

    # The bogus name must never correspond to a real environment record.
    ghost = eb.describe_environments(EnvironmentNames=[bogus_env_name], IncludeDeleted=False)["Environments"]
    assert ghost == [], f"unexpected environment materialized for a bogus name: {ghost}"


def _error_code(fn):
    """Return the (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

