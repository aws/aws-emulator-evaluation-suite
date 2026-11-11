"""missing-permission-describe-artifact-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-permission-describe-artifact-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeArtifact via a role with no SageMaker permissions is denied."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-artifact-perm-")
    source_uri = f"s3://sim2real-behav-bucket/{name}/data.csv"

    created = sm.create_artifact(
        ArtifactName=name,
        ArtifactType="DataSet",
        Source={"SourceUri": source_uri},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    artifact_arn = created["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_best_effort(sm, artifact_arn))

    restricted_sm, assumed_arn = _restricted_sagemaker_client(ctx)

    code, message = _error(lambda: restricted_sm.describe_artifact(ArtifactArn=artifact_arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException from a no-permission role, got {code!r}"
    expected_message = (
        f"User: {assumed_arn} is not authorized to perform: sagemaker:DescribeArtifact on "
        f"resource: {artifact_arn} because no identity-based policy allows the "
        "sagemaker:DescribeArtifact action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control in the same file: the original (permitted) identity still succeeds,
    # proving the denial above is specific to the missing permission, not a broken artifact
    # or a blanket rejection by the backend.
    desc = sm.describe_artifact(ArtifactArn=artifact_arn)
    assert desc["ArtifactArn"] == artifact_arn, f"expected ArtifactArn {artifact_arn!r}, got {desc['ArtifactArn']!r}"
    assert desc["Source"]["SourceUri"] == source_uri, (
        f"expected SourceUri {source_uri!r}, got {desc['Source']['SourceUri']!r}"
    )


def _delete_artifact_best_effort(sm, artifact_arn: str) -> None:
    try:
        sm.delete_artifact(ArtifactArn=artifact_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _restricted_sagemaker_client(ctx):
    """Create an IAM role with NO permissions policy attached, assume it, and return a
    sagemaker client built from those (permission-less) credentials, together with the
    assumed-role session ARN that AWS names in its denial."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-noperm-role-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral check: role with no attached permissions",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_best_effort(iam, role_name))

    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behavioral-noperm"
            )
            creds = assumed["Credentials"]
            # ctx.client keeps THIS target's endpoint/TLS wiring while signing with the
            # permission-less identity; a bare boto3.client would answer the AccessDeniedException
            # assertion from real AWS even when the target under test is an emulator.
            return ctx.client(
                "sagemaker",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            ), assumed["AssumedRoleUser"]["Arn"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not assume no-permission role in time: {last_exc}")


def _delete_role_best_effort(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
