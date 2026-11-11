"""codebuild-retry-build-reuses-the-pinned-source-version-after-the-object-changes."""
from __future__ import annotations

import io
import json
import string
import time
import zipfile
import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-retry-source-pin"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role after its inline policies; NoSuchEntity means it is already gone."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_service_role(ctx, statements):
    """Mint a real CodeBuild-assumable service role carrying exactly `statements`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codebuild-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return resp["Role"]["Arn"]


def _create_bucket(s3, bucket_name, region):
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name,
                         CreateBucketConfiguration={"LocationConstraint": region})


def _empty_and_delete_versioned_bucket(s3, bucket_name):
    """Purge every object VERSION and delete marker, then the bucket itself."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket_name):
            doomed = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                      for v in page.get("Versions", [])]
            doomed += [{"Key": m["Key"], "VersionId": m["VersionId"]}
                       for m in page.get("DeleteMarkers", [])]
            if doomed:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": doomed})
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _upload_source_zip(s3, bucket, key, files):
    """Write a ZIP of {name: content} to S3 and return the object's VersionId."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    resp = s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    version = resp.get("VersionId")
    assert version and version != "null", (
        f"the source bucket must have versioning ENABLED before the first upload - PutObject "
        f"returned VersionId {version!r} for s3://{bucket}/{key}"
    )
    return version


def _create_project(cb, ctx, name, role_arn, source, buildspec, **over):
    """CreateProject with an explicit source, retrying through IAM trust-policy propagation;
    registers teardown immediately on success. Returns the project dict."""
    args = {
        "name": name,
        "source": dict(source, buildspec=buildspec),
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {"type": "LINUX_CONTAINER", "image": _IMAGE,
                        "computeType": "BUILD_GENERAL1_SMALL"},
        "serviceRole": role_arn,
        "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"},
                       "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 5,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    # Trust propagation exposes no condition to poll, so this bounded retry IS the wait.
    deadline = time.monotonic() + _budget_s(ctx, 180)
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if transient_role and _budget_spent(ctx):
                raise TimeoutError("CreateProject past the role's trust propagation: the run budget ended first; not graded") from exc
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _stop(cb, build_id):
    try:
        cb.stop_build(id=build_id)
    except ClientError as exc:
        # The build is already terminal (InvalidInputException) or gone: nothing left to stop.
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "ResourceNotFoundException"):
            raise


def _register_stop(cb, ctx):
    """Return a holder whose StopBuild cleanup is registered before the build id exists, so a
    build that starts and then trips an assertion is still stopped."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    return holder


def _get_builds(cb, ids):
    got = cb.batch_get_builds(ids=list(ids))
    by_id = {b["id"]: b for b in got.get("builds", [])}
    missing = [i for i in ids if i not in by_id]
    assert not missing, (
        f"BatchGetBuilds lost {missing!r}; asked for {list(ids)!r}, got {sorted(by_id)!r} "
        f"and buildsNotFound={got.get('buildsNotFound')!r}"
    )
    return by_id


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_builds_terminal(ctx, cb, ids, *, timeout_s, interval_s=1.0):
    """Poll BatchGetBuilds until every id reports buildComplete; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        by_id = _get_builds(cb, ids)
        pending = [i for i, b in by_id.items() if b.get("buildComplete") is not True]
        if not pending:
            return by_id
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"builds {pending!r} reporting buildComplete: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"after {timeout_s:.0f}s these builds never reported buildComplete: "
            f"{[(i, by_id[i].get('buildStatus'), by_id[i].get('currentPhase')) for i in pending]!r}"
        )
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _exported(build):
    return {v["name"]: v["value"]
            for v in build.get("exportedEnvironmentVariables") or []}


def _token(n=10):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(n))


_BUILDSPEC = (
    "version: 0.2\n"
    "env:\n"
    "  exported-variables:\n"
    "    - SIM2REAL_PAYLOAD\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    '      - export SIM2REAL_PAYLOAD="$(cat payload.txt)"\n'
)


CHECK = "codebuild-retry-build-reuses-the-pinned-source-version-after-the-object-changes"
GROUP = 'artifacts'
SERVICES = ['codebuild', 's3']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A build pinned to an S3 object version reads its bytes; after an overwrite, RetryBuild reuses
    the pinned sourceVersion and original bytes, while a fresh unpinned StartBuild reads the new ones.

    Reference: https://docs.aws.amazon.com/codebuild/latest/APIReference/API_RetryBuild.html"""
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")

    payload_v1 = _token()
    payload_v2 = _token()
    assert payload_v1 != payload_v2, "the two payload tokens must differ"

    bucket = ctx.unique_name("sim2real-behav-cb-src-").lower().replace("_", "-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_versioned_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket,
                             VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})

    key = "source.zip"
    version_1 = _upload_source_zip(s3, bucket, key, {"payload.txt": payload_v1})

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketAcl",
                    "s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions"],
         "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
    ])

    name = ctx.unique_name("sim2real-behav-proj-retrysrc-")
    _create_project(cb, ctx, name, role,
                    {"type": "S3", "location": f"{bucket}/{key}"}, _BUILDSPEC)

    # RetryBuild needs the original build terminal, so it finishes before the overwrite.
    holder_1 = _register_stop(cb, ctx)
    original = cb.start_build(projectName=name, sourceVersion=version_1)["build"]
    holder_1["id"] = original["id"]
    first = _poll_builds_terminal(
        ctx, cb, [original["id"]], timeout_s=_budget_s(ctx, 300))[original["id"]]

    assert first["buildStatus"] == "SUCCEEDED", (
        f"the pinned build must succeed for its bytes to be evidence; got "
        f"{first['buildStatus']!r}; phases={_phases(first)!r}; "
        f"contexts={[p.get('contexts') for p in first.get('phases', [])]!r}"
    )
    assert first.get("sourceVersion") == version_1, (
        f"the build must report the S3 object version it was pinned to ({version_1!r}), it "
        f"reports {first.get('sourceVersion')!r}"
    )
    assert _exported(first).get("SIM2REAL_PAYLOAD") == payload_v1, (
        f"the container must have read version 1's payload {payload_v1!r} out of the unzipped "
        f"source; it exported {_exported(first).get('SIM2REAL_PAYLOAD')!r} "
        f"(all exported: {_exported(first)!r})"
    )
    resolved_1 = first.get("resolvedSourceVersion")
    assert not resolved_1, (
        f"the CodeBuild API reference is explicit that resolvedSourceVersion 'does not apply' "
        f"for an S3 source, so an S3-sourced build must report it falsy; it reports "
        f"{resolved_1!r}"
    )

    version_2 = _upload_source_zip(s3, bucket, key, {"payload.txt": payload_v2})
    assert version_2 != version_1, (
        f"the overwrite must mint a NEW object version; both uploads returned {version_1!r}"
    )
    versions = sorted(
        v["VersionId"]
        for page in s3.get_paginator("list_object_versions").paginate(
            Bucket=bucket, Prefix=key)
        for v in page.get("Versions", []))
    assert versions == sorted([version_1, version_2]), (
        f"s3://{bucket}/{key} must hold exactly the two versions this check uploaded "
        f"{sorted([version_1, version_2])!r}; it holds {versions!r}"
    )

    holder_retry = _register_stop(cb, ctx)
    retried = cb.retry_build(id=original["id"])["build"]
    holder_retry["id"] = retried["id"]
    holder_fresh = _register_stop(cb, ctx)
    fresh = cb.start_build(projectName=name)["build"]
    holder_fresh["id"] = fresh["id"]
    assert len({original["id"], retried["id"], fresh["id"]}) == 3, (
        f"the three builds must have distinct ids, got "
        f"{[original['id'], retried['id'], fresh['id']]!r}"
    )

    final = _poll_builds_terminal(ctx, cb, [retried["id"], fresh["id"]], timeout_s=_budget_s(ctx, 360))
    retry_final = final[retried["id"]]
    fresh_final = final[fresh["id"]]

    # Positive control: the overwrite IS visible to a build that does not pin a version.
    assert fresh_final["buildStatus"] == "SUCCEEDED", (
        f"the fresh control build must succeed; got {fresh_final['buildStatus']!r}; "
        f"phases={_phases(fresh_final)!r}; "
        f"contexts={[p.get('contexts') for p in fresh_final.get('phases', [])]!r}"
    )
    assert _exported(fresh_final).get("SIM2REAL_PAYLOAD") == payload_v2, (
        f"an unpinned build after the overwrite must read the NEW payload {payload_v2!r} - "
        f"without this leg, the retry reading the old payload could just mean the overwrite "
        f"never took effect. It exported "
        f"{_exported(fresh_final).get('SIM2REAL_PAYLOAD')!r} "
        f"(all exported: {_exported(fresh_final)!r})"
    )

    # The subject: the retry is pinned to the ORIGINAL bytes.
    assert retry_final["buildStatus"] == "SUCCEEDED", (
        f"the retried build must succeed; got {retry_final['buildStatus']!r}; "
        f"phases={_phases(retry_final)!r}; "
        f"contexts={[p.get('contexts') for p in retry_final.get('phases', [])]!r}"
    )
    assert retry_final.get("sourceVersion") == version_1, (
        f"RetryBuild must reuse the original build's pinned sourceVersion {version_1!r}, not "
        f"the newest {version_2!r}; the retry reports {retry_final.get('sourceVersion')!r}"
    )
    assert _exported(retry_final).get("SIM2REAL_PAYLOAD") == payload_v1, (
        f"the retry must have downloaded the ORIGINAL object version and read {payload_v1!r}, "
        f"not the overwritten {payload_v2!r}; it exported "
        f"{_exported(retry_final).get('SIM2REAL_PAYLOAD')!r} "
        f"(all exported: {_exported(retry_final)!r})"
    )
    assert not retry_final.get("resolvedSourceVersion"), (
        f"resolvedSourceVersion still does not apply to an S3 source on a retry; it reports "
        f"{retry_final.get('resolvedSourceVersion')!r}"
    )
    assert not fresh_final.get("resolvedSourceVersion"), (
        f"resolvedSourceVersion still does not apply to an S3 source on a fresh unpinned build; "
        f"it reports {fresh_final.get('resolvedSourceVersion')!r}"
    )

    assert retry_final.get("projectName") == first.get("projectName"), (
        f"the retry must belong to the same project {first.get('projectName')!r}; it reports "
        f"{retry_final.get('projectName')!r}"
    )
    # Strictly greater, not +1: the concurrent control build also consumes a build number.
    assert retry_final.get("buildNumber") > first.get("buildNumber"), (
        f"the retry must take a build number above the original's "
        f"{first.get('buildNumber')!r}; it reports {retry_final.get('buildNumber')!r}"
    )

    listed = []
    token = None
    while True:
        kwargs = {"projectName": name}
        if token:
            kwargs["nextToken"] = token
        page = cb.list_builds_for_project(**kwargs)
        listed.extend(page.get("ids", []))
        token = page.get("nextToken")
        if not token:
            break
    assert sorted(listed) == sorted([original["id"], retried["id"], fresh["id"]]), (
        f"ListBuildsForProject must report exactly the three builds this check started for "
        f"{name!r}; it reported {sorted(listed)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
