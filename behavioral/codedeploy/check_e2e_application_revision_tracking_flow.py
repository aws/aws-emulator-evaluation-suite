"""e2e-application-revision-tracking-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-application-revision-tracking-flow"
GROUP = "e2e"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Register an application revision, deploy referencing it, and confirm the
    deployment's revision matches and ListApplicationRevisions/BatchGetApplicationRevisions
    reflect it end-to-end before teardown."""
    cd = ctx.client("codedeploy")
    role_arn = _create_service_role(ctx)

    app = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app, computePlatform="Server", tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app))

    description = "sim2real e2e tracked revision"
    revision = _upload_s3_revision(ctx)
    cd.register_application_revision(applicationName=app, revision=revision["location"], description=description)

    group = ctx.unique_name("sim2real-cd-dg-")
    _create_deployment_group(
        ctx, cd, app, group, role_arn,
        onPremisesInstanceTagFilters=[
            {"Key": ctx.unique_name("sim2real-nomatch-"), "Value": "none", "Type": "KEY_AND_VALUE"}
        ],
    )

    deployment_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=group, revision=revision["location"]
    )["deploymentId"]

    # Hinge 1: the deployment's own record must carry the exact revision we registered.
    deployed_revision = cd.get_deployment(deploymentId=deployment_id)["deploymentInfo"]["revision"]["s3Location"]
    assert deployed_revision["bucket"] == revision["bucket"], deployed_revision
    assert deployed_revision["key"] == revision["key"], deployed_revision

    # Hinge 2: the revision is discoverable via ListApplicationRevisions.
    listed = cd.list_application_revisions(applicationName=app)["revisions"]
    matches = [
        r for r in listed
        if r.get("s3Location", {}).get("bucket") == revision["bucket"]
        and r.get("s3Location", {}).get("key") == revision["key"]
    ]
    assert len(matches) == 1, listed

    # Hinge 3: BatchGetApplicationRevisions reflects the registered description with no error.
    batch = cd.batch_get_application_revisions(applicationName=app, revisions=[revision["location"]])
    assert batch.get("errorMessage") in (None, ""), batch
    assert len(batch["revisions"]) == 1, batch["revisions"]
    got_info = batch["revisions"][0]["genericRevisionInfo"]
    assert got_info["description"] == description, got_info


def _create_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_deployment_group(ctx, cd, application_name, deployment_group_name, service_role_arn, **kwargs):
    deadline = time.monotonic() + 30
    while True:
        try:
            resp = cd.create_deployment_group(
                applicationName=application_name,
                deploymentGroupName=deployment_group_name,
                serviceRoleArn=service_role_arn,
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: cd.delete_deployment_group(
        applicationName=application_name, deploymentGroupName=deployment_group_name
    ))
    return resp


def _minimal_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", "version: 0.0\nos: linux\nfiles: []\n")
    return buf.getvalue()


def _upload_s3_revision(ctx, key="revision.zip"):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 (its own default).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return {
        "bucket": bucket,
        "key": key,
        "location": {"revisionType": "S3", "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"}},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
