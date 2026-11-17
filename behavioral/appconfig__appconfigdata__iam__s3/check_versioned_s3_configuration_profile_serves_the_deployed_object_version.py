"""versioned-s3-configuration-profile-serves-the-deployed-object-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "versioned-s3-configuration-profile-serves-the-deployed-object-version"
GROUP = "configuration-data-plane"
SERVICES = ["appconfig", "appconfigdata", "iam", "s3"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-s3-version-pin"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]

#: Two byte-exact documents, so "the data plane serves the DEPLOYED object version" can be told
#: apart from "the data plane serves whatever is currently at the key".
_V1_BYTES = b'{"useNewBackend": true}'
_V2_BYTES = b'{"useNewBackend": false}'

_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ROLE_PROPAGATION_TIMEOUT_S = 300


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


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=180):
    """Poll fresh sessions until one is served exactly `expect`; return the last payload seen."""
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        body = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
        if body == expect or time.monotonic() >= deadline:
            return body
        time.sleep(3.0)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Freeform profile backed by a versioned S3 object serves the exact version id a
    deployment named, through StartConfigurationSession and GetLatestConfiguration, and
    deploying a second version id changes what every new session is served.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    bucket = ctx.unique_name("sim2real-behav-s3cfg-")
    key = "config.json"
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": ctx.region},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    version_one = s3.put_object(Bucket=bucket, Key=key, Body=_V1_BYTES)["VersionId"]
    version_two = s3.put_object(Bucket=bucket, Key=key, Body=_V2_BYTES)["VersionId"]
    assert version_one != version_two, (
        f"two distinct PutObject calls to a versioned bucket must mint distinct version ids; "
        f"got {version_one!r} twice"
    )
    # The expected bytes come from the SOURCE, not from a literal re-read here.
    confirmed_one = s3.get_object(Bucket=bucket, Key=key, VersionId=version_one)["Body"].read()
    assert confirmed_one == _V1_BYTES, (
        f"S3 must serve back version {version_one!r} byte-exact; got {confirmed_one!r}"
    )

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

    # AppConfig validates it can assume RetrievalRoleArn at CreateConfigurationProfile time; a
    # fresh role's trust policy may not have propagated yet, which yields
    # `BadRequestException: Error trying to assume role <arn>`, so retry here.
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
    assert (cp["LocationUri"], cp["RetrievalRoleArn"], cp["Type"]) == (
        location_uri,
        retrieval_role_arn,
        "AWS.Freeform",
    ), (
        f"the profile must record the S3 source, its retrieval role and its type; got "
        f"{(cp.get('LocationUri'), cp.get('RetrievalRoleArn'), cp.get('Type'))!r}"
    )

    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    first = _deploy_with_role_propagation_retry(
        ac,
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=version_one,
        Tags=_TAGS,
    )
    first = _wait_terminal(ac, app_id, env_id, first["DeploymentNumber"])
    assert first["State"] == "COMPLETE", (
        f"deploying S3 object version {version_one!r} must reach COMPLETE; got {first['State']!r}"
    )
    assert (first["ConfigurationVersion"], first["ConfigurationLocationUri"]) == (
        version_one,
        location_uri,
    ), (
        f"the deployment must record the exact S3 object version id and source it read; got "
        f"{(first.get('ConfigurationVersion'), first.get('ConfigurationLocationUri'))!r}"
    )

    served_one = _serve_until(acd, app_id, env_id, cp_id, expect=_V1_BYTES)
    assert served_one == _V1_BYTES, (
        f"a session opened after the deployment of version {version_one!r} must be served that "
        f"version's bytes; got {served_one!r}"
    )

    # --- A second deployment naming the SECOND object version changes what new sessions get.
    second = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=version_two,
        Tags=_TAGS,
    )
    second = _wait_terminal(ac, app_id, env_id, second["DeploymentNumber"])
    assert second["State"] == "COMPLETE", (
        f"deploying S3 object version {version_two!r} must reach COMPLETE; got {second['State']!r}"
    )
    assert second["ConfigurationVersion"] == version_two, (
        f"the second deployment must record the second object version id; got "
        f"{second.get('ConfigurationVersion')!r}"
    )

    served_two = _serve_until(acd, app_id, env_id, cp_id, expect=_V2_BYTES)
    assert served_two == _V2_BYTES, (
        f"a session opened after the deployment of version {version_two!r} must be served that "
        f"version's bytes, not the first version's; expected {_V2_BYTES!r}, got {served_two!r}"
    )

    history = _purge_items(
        ac.get_paginator("list_deployments").paginate(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert [d["ConfigurationVersion"] for d in sorted(history, key=lambda d: d["DeploymentNumber"])] == [
        version_one,
        version_two,
    ], (
        f"the environment's deployment history must record the two object versions in order they "
        f"were deployed; got {[d['ConfigurationVersion'] for d in history]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
