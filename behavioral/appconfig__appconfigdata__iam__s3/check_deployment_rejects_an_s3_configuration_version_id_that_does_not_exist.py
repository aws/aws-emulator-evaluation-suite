"""deployment-rejects-an-s3-configuration-version-id-that-does-not-exist."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deployment-rejects-an-s3-configuration-version-id-that-does-not-exist"
GROUP = "ordering-boundary"
SERVICES = ["appconfig", "appconfigdata", "iam", "s3"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-s3-bogus-version-rejected"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]

_V1_BYTES = b'{"useNewBackend": true}'
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ROLE_PROPAGATION_TIMEOUT_S = 300

#: The fixed shape of the error AWS returns, with the two per-call identifiers it issues itself
#: (never ours to predict) normalized to placeholders before comparison.
_EXPECTED_REJECTION_MESSAGE = (
    "An error occurred when calling the S3 GetObjectMetadata operation: Forbidden "
    "(Service: Amazon S3; Status Code: 403; Error Code: 403 Forbidden; "
    "Request ID: <id>; S3 Extended Request ID: <id>; Proxy: null)"
)
_REQUEST_ID_PATTERN = re.compile(r"Request ID: [^;]+; S3 Extended Request ID: [^;]+;")


def _normalize_request_ids(message: str) -> str:
    """Replace AWS's two per-call, per-run identifiers with a fixed placeholder."""
    return _REQUEST_ID_PATTERN.sub("Request ID: <id>; S3 Extended Request ID: <id>;", message)


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=240):
    """Delete an application and everything beneath it, bottom-up. Raises rather than leaking."""
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=profile["Id"],
            DeletionProtectionCheck="BYPASS",
        )
    for env in environments:
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object version and delete marker, then the bucket itself."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objects += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
        ]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


def _make_role(ctx, iam, trusted_service, statements):
    """Create a role trusted by one AWS service with one inline policy."""
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trusted_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _wait_terminal(ac, app_id, env_id, dep_num, timeout_s=240):
    """Poll GetDeployment until the deployment reaches a terminal state. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"deployment {dep_num} never reached a terminal state within {timeout_s}s; last state "
        f"{(last or {}).get('State')!r}"
    )


#: A freshly assumed role's temporary credentials can be rejected by S3 for a short window after
#: IAM/STS mint them, in either of two shapes: AppConfig cannot assume the role yet, or it assumed
#: it but the resulting access key has not yet propagated to the edge S3 saw the request on.
_ROLE_PROPAGATION_MESSAGE_MARKERS = (
    "assume role",
    "AWS Access Key Id you provided does not exist in our records",
    "is not authorized to perform",
)


def _is_role_propagation_error(err: dict) -> bool:
    if err.get("Code") != "BadRequestException":
        return False
    message = err.get("Message") or ""
    return any(marker in message for marker in _ROLE_PROPAGATION_MESSAGE_MARKERS)


def _deploy_with_role_propagation_retry(ac, **kwargs):
    """StartDeployment, retrying only the role-propagation window a fresh retrieval role hits."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_error = None
    while time.monotonic() < deadline:
        try:
            return ac.start_deployment(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if not _is_role_propagation_error(err):
                raise
            last_error = err
            time.sleep(2.0)
    raise AssertionError(
        f"StartDeployment never got past role-assumption propagation within "
        f"{_ROLE_PROPAGATION_TIMEOUT_S}s; last error {last_error!r}"
    )


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """StartDeployment naming an S3 object version id that does not exist on the source key
    is refused, and the environment's deployment history gains no record of the attempt.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    bucket = ctx.unique_name("sim2real-behav-s3cfg-")
    key = "config.json"
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    version_one = s3.put_object(Bucket=bucket, Key=key, Body=_V1_BYTES)["VersionId"]

    # A syntactically plausible but never-minted version id: same length as a real one, built from
    # characters S3 version ids use, but S3 itself never handed it out for this key.
    bogus_version = "x" * len(version_one)
    assert bogus_version != version_one, "the bogus id must differ from the real one"

    retrieval_role_arn = _make_role(
        ctx,
        iam,
        "appconfig.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "s3:GetBucketLocation", "Resource": f"arn:aws:s3:::{bucket}"},
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
            },
        ],
    )

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    location_uri = f"s3://{bucket}/{key}"

    cp = None
    deadline_cp = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_error_cp = None
    while time.monotonic() < deadline_cp:
        try:
            cp = ac.create_configuration_profile(
                ApplicationId=app_id,
                Name=ctx.unique_name("sim2real-behav-cp-"),
                LocationUri=location_uri,
                RetrievalRoleArn=retrieval_role_arn,
                Type="AWS.Freeform",
                Tags=_TAGS,
            )
            break
        except ClientError as exc:
            last_error_cp = exc.response.get("Error", {})
            if not _is_role_propagation_error(last_error_cp):
                raise
            time.sleep(2.0)
    assert cp is not None, (
        f"CreateConfigurationProfile never accepted retrieval role {retrieval_role_arn!r} within "
        f"{_ROLE_PROPAGATION_TIMEOUT_S}s; last error {last_error_cp!r}"
    )
    cp_id = cp["Id"]

    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # --- Positive control: the real object version deploys and serves cleanly on this exact
    #     wiring, so a refusal of the bogus id below is about THAT id, not a broken setup.
    control = _deploy_with_role_propagation_retry(
        ac,
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=version_one,
        Tags=_TAGS,
    )
    control_num = control["DeploymentNumber"]
    control = _wait_terminal(ac, app_id, env_id, control_num)
    assert control["State"] == "COMPLETE", (
        f"deploying the real object version {version_one!r} must reach COMPLETE; got "
        f"{control['State']!r}"
    )
    token = acd.start_configuration_session(
        ApplicationIdentifier=app_id, EnvironmentIdentifier=env_id, ConfigurationProfileIdentifier=cp_id
    )["InitialConfigurationToken"]
    served = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
    assert served == _V1_BYTES, (
        f"the positive control must serve the real object version's bytes; got {served!r}"
    )
    history_before = _purge_items(
        ac.get_paginator("list_deployments").paginate(ApplicationId=app_id, EnvironmentId=env_id)
    )
    deployment_numbers_before = {d["DeploymentNumber"] for d in history_before}
    assert deployment_numbers_before == {control_num}, (
        f"before the rejected attempt only the control deployment must exist; got "
        f"{sorted(deployment_numbers_before)!r}"
    )

    # --- THE POINT: a version id that was never minted for this key is refused synchronously.
    try:
        ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=bogus_version,
            Tags=_TAGS,
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        message = err.get("Message") or ""
    else:
        raise AssertionError(
            "StartDeployment SUCCEEDED for an S3 object version id that was never minted for "
            "this key — this is an over-permissiveness failure, not an error-code mismatch"
        )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert _normalize_request_ids(message) == _EXPECTED_REJECTION_MESSAGE, (
        f"expected (modulo AWS's own per-call request ids) {_EXPECTED_REJECTION_MESSAGE!r}, got "
        f"{_normalize_request_ids(message)!r} (raw: {message!r})"
    )

    # --- Independent read: the rejected attempt left no new deployment behind.
    history_after = _purge_items(
        ac.get_paginator("list_deployments").paginate(ApplicationId=app_id, EnvironmentId=env_id)
    )
    deployment_numbers_after = {d["DeploymentNumber"] for d in history_after}
    assert deployment_numbers_after == {control_num}, (
        f"a refused StartDeployment must create no deployment record; before "
        f"{sorted(deployment_numbers_before)!r}, after {sorted(deployment_numbers_after)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
