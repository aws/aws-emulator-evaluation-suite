"""start-build-artifacts-override-rejected-without-a-location-and-no-artifacts-uploads-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-build-artifacts-override-rejected-without-a-location-and-no-artifacts-uploads-nothing"
GROUP = "overrides"
SERVICES = ["codebuild"]

_ARTIFACT_NAME = "out"
_BUILDSPEC = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    '      - echo "built by $CODEBUILD_BUILD_NUMBER" > result.txt\n'
    "artifacts:\n"
    "  files:\n"
    "    - result.txt\n"
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _empty_and_delete(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for o in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=o["Key"])
    s3.delete_bucket(Bucket=bucket)


def _keys(s3, bucket: str) -> list:
    return sorted(o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
                  for o in page.get("Contents", []))


def _create_role(ctx, iam, bucket: str) -> str:
    """A CodeBuild service role that may write this check's bucket; returns its ARN."""
    name = ctx.unique_name("sim2real-behav-cb-art-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, Path="/sim2real/",
                          AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": "codebuild-artifacts"}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="artifacts", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Resource": "*",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]},
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketAcl", "s3:GetBucketLocation"],
             "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"),
                             "NoSuchEntity"))
    return arn


def _create_project(ctx, cb, name: str, role: str, bucket: str) -> dict:
    """CreateProject, retrying while the new role's trust policy propagates (IAM exposes no
    condition to poll); the retry is bounded and keyed on the propagation message."""
    deadline = time.monotonic() + 90
    while True:
        try:
            project = cb.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
                artifacts={"type": "S3", "location": bucket, "name": _ARTIFACT_NAME,
                           "packaging": "NONE", "namespaceType": "BUILD_ID"},
                cache={"type": "NO_CACHE"},
                environment={"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0",
                             "computeType": "BUILD_GENERAL1_SMALL"},
                serviceRole=role,
                timeoutInMinutes=5,
                logsConfig={"cloudWatchLogs": {"status": "DISABLED"},
                            "s3Logs": {"status": "DISABLED"}},
                tags=[{"key": "sim2real", "value": "codebuild-artifacts"}],
            )["project"]
            break
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "InvalidInputException"
                           and "not authorized to perform: sts:AssumeRole" in err.get("Message", ""))
            if propagating and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(_teardown(lambda: cb.delete_project(name=name), "ResourceNotFoundException"))
    return project


def _start(ctx, cb, **kwargs) -> dict:
    """StartBuild with a stop registered first; the stop runs only while the build is live."""
    holder: dict = {}

    def stop() -> None:
        bid = holder.get("id")
        if not bid:
            return
        builds = cb.batch_get_builds(ids=[bid]).get("builds", [])
        if builds and builds[0].get("buildComplete") is not True:
            cb.stop_build(id=bid)

    ctx.on_cleanup(stop)
    build = cb.start_build(**kwargs)["build"]
    holder["id"] = build["id"]
    return build


def _until_complete(cb, build_id: str, *, timeout_s: float = 600) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        builds = cb.batch_get_builds(ids=[build_id]).get("builds", [])
        assert builds, f"BatchGetBuilds lost a build this check started: {build_id!r}"
        if builds[0].get("buildComplete") is True:
            return builds[0]
        if time.monotonic() >= deadline:
            raise AssertionError(f"build not complete within {timeout_s}s: "
                                 f"{builds[0].get('buildStatus')!r}")
        time.sleep(5)


def _project_build_ids(cb, name: str) -> set:
    ids, kwargs = set(), {"projectName": name}
    while True:
        page = cb.list_builds_for_project(**kwargs)
        ids.update(page.get("ids", []))
        if not page.get("nextToken"):
            return ids
        kwargs["nextToken"] = page["nextToken"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """StartBuild refuses an S3 artifactsOverride without a location, or naming a missing bucket, with
    InvalidInputException; a NO_ARTIFACTS override uploads nothing, while a build without it uploads
    its file under its build id."""
    cb = ctx.client("codebuild")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cb-art-")
    params: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 must not be named as a LocationConstraint; every other region must be.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete(s3, bucket), "NoSuchBucket"))
    missing_bucket = ctx.unique_name("sim2real-behav-cb-missing-")

    role = _create_role(ctx, iam, bucket)
    name = ctx.unique_name("sim2real-behav-cb-art-")
    _create_project(ctx, cb, name, role, bucket)

    # --- the refusals: no location, and a bucket that does not exist -----------------
    code, msg = _err(lambda: cb.start_build(projectName=name, artifactsOverride={"type": "S3"}))
    assert (code, msg) == ("InvalidInputException", "Invalid artifacts: location is required"), (
        f"an S3 artifactsOverride without a location must be refused, got {code!r}: {msg!r}"
    )
    code, msg = _err(lambda: cb.start_build(
        projectName=name, artifactsOverride={"type": "S3", "location": missing_bucket}))
    assert (code, msg) == ("InvalidInputException", f"Bucket {missing_bucket} does not exist"), (
        f"an artifactsOverride naming a missing bucket must be refused, got {code!r}: {msg!r}"
    )

    # --- NO_ARTIFACTS for one build, the project's S3 artifacts for the next ----------
    silent = _start(ctx, cb, projectName=name, artifactsOverride={"type": "NO_ARTIFACTS"})
    done_silent = _until_complete(cb, silent["id"])
    assert done_silent["buildStatus"] == "SUCCEEDED", (
        f"the NO_ARTIFACTS build ended {done_silent['buildStatus']!r}"
    )
    assert not done_silent.get("artifacts", {}).get("location"), (
        f"the NO_ARTIFACTS build reports an artifact location: {done_silent.get('artifacts')!r}"
    )
    assert _keys(s3, bucket) == [], (
        f"the NO_ARTIFACTS build uploaded {_keys(s3, bucket)!r} to the project's bucket"
    )

    uploaded = _start(ctx, cb, projectName=name)
    done = _until_complete(cb, uploaded["id"])
    assert done["buildStatus"] == "SUCCEEDED", f"the default build ended {done['buildStatus']!r}"
    build_uuid = done["id"].split(":", 1)[1]
    expected_key = f"{build_uuid}/{_ARTIFACT_NAME}/result.txt"
    assert done.get("artifacts", {}).get("location") == (
        f"arn:aws:s3:::{bucket}/{build_uuid}/{_ARTIFACT_NAME}"), (
        f"the default build reports artifact location {done.get('artifacts', {}).get('location')!r}"
    )
    assert _keys(s3, bucket) == [expected_key], (
        f"the project's bucket holds {_keys(s3, bucket)!r}; expected exactly the default "
        f"build's file under its build id"
    )
    body = s3.get_object(Bucket=bucket, Key=expected_key)["Body"].read()
    assert body == f"built by {done['buildNumber']}\n".encode(), (
        f"the uploaded artifact reads {body!r}, expected the default build's own output"
    )

    # --- effect absent: the refused StartBuild calls created no build -----------------
    want = {silent["id"], uploaded["id"]}
    ids: set = set()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        ids = _project_build_ids(cb, name)
        if want <= ids:
            break
        time.sleep(3)
    assert ids == want, (
        f"the project lists {len(ids)} builds; expected exactly the {len(want)} this check "
        f"started (extra: {len(ids - want)}, missing: {len(want - ids)})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
