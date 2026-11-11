"""create-environment-invalid-execution-role-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-environment-invalid-execution-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment rejects an ExecutionRoleArn that does not match the required
    arn:aws:iam::<account>:role/... pattern with ValidationException, and no environment is created."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-badarn-")

    code, message = _error(
        lambda: mwaa.create_environment(
            Name=name,
            ExecutionRoleArn="not-a-valid-role-arn",
            SourceBucketArn="arn:aws:s3:::some-bucket-name",
            DagS3Path="dags",
            NetworkConfiguration={
                "SubnetIds": ["subnet-00000000000000001", "subnet-00000000000000002"],
                "SecurityGroupIds": ["sg-00000000000000001"],
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, actual_code={code!r}"
    assert message == (
        "1 validation error detected: Value 'not-a-valid-role-arn' at 'executionRoleArn' failed to"
        " satisfy constraint: Member must satisfy regular expression pattern:"
        r" arn:aws(-[a-z]+)?:iam::\d{12}:role/?[a-zA-Z_0-9+=,.@\-_/]+"
    ), message

    # Effect absent: no environment record was created under that name.
    not_found_code, not_found_message = _error(lambda: mwaa.get_environment(Name=name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, actual_code={not_found_code!r}"
    )
    assert not_found_message == f"Environment {name} not found.", not_found_message

    # Positive control: the mwaa API itself is not just blanket-rejecting every call in
    # this account/region (an emulator that unconditionally errors would fail this too).
    control = mwaa.list_environments(MaxResults=5)
    assert "Environments" in control, f"expected an Environments key, actual={control!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
