"""codebuild-s3-cache-carries-a-file-from-one-build-into-the-next."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_SCENARIO = "codebuild-s3-cache"
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
    # IAM propagation has no condition to poll; _create_project retries through it.
    return resp["Role"]["Arn"]


def _create_bucket(s3, bucket_name, region):
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name,
                         CreateBucketConfiguration={"LocationConstraint": region})


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _list_keys(s3, bucket, prefix=""):
    """Every key under `prefix`, across all pages."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _create_project(cb, ctx, name, role_arn, buildspec, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown immediately on success. Returns the project dict."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
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
    deadline = time.monotonic() + 120
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
                time.sleep(3)
                continue
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


def _start_build_with_stop_registered(cb, ctx, **kwargs):
    """Register the StopBuild cleanup BEFORE issuing StartBuild, so a build that starts and
    then trips an assertion still gets stopped instead of billing its whole timeout."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
    """Poll BatchGetBuilds until buildComplete, bounded by a deadline. Returns the terminal
    Build dict, or None if the deadline passed while it was still running."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, f"BatchGetBuilds lost build {build_id!r}: {got!r}"
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]


def _poll_keys(s3, bucket, prefix, want_nonempty, *, timeout_s):
    """Poll the cache prefix until it is (non-)empty as required, bounded. Returns the last
    listing seen so the caller can put the real keys in its failure message."""
    deadline = time.monotonic() + timeout_s
    while True:
        keys = _list_keys(s3, bucket, prefix)
        if bool(keys) is want_nonempty:
            return keys
        if time.monotonic() >= deadline:
            return keys
        time.sleep(3)


# ===== check =====

CHECK = "codebuild-s3-cache-carries-a-file-from-one-build-into-the-next"
GROUP = 'cache'
SERVICES = ['codebuild', 's3']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A token one build writes to a cached path is read back by the next build via the S3 cache;
    after InvalidateProjectCache a third build misses even though the S3 cache object remains.
    """
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cb-cache-").lower().replace("_", "-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:GetBucketAcl",
                    "s3:GetBucketLocation", "s3:ListBucket"],
         "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
    ])

    buildspec = (
        "version: 0.2\n"
        "env:\n"
        "  exported-variables:\n"
        "    - SIM2REAL_CACHE_STATE\n"
        "    - SIM2REAL_CACHE_VALUE\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - mkdir -p sim2real-cache\n"
        "      - |\n"
        "        if [ -f sim2real-cache/token ]; then\n"
        "          export SIM2REAL_CACHE_STATE=hit\n"
        '          export SIM2REAL_CACHE_VALUE="$(cat sim2real-cache/token)"\n'
        "        else\n"
        '          printf \'%s\' "$SIM2REAL_TOKEN" > sim2real-cache/token\n'
        "          export SIM2REAL_CACHE_STATE=miss\n"
        "          export SIM2REAL_CACHE_VALUE=cold\n"
        "        fi\n"
        "cache:\n"
        "  paths:\n"
        "    - 'sim2real-cache/**/*'\n"
    )

    name = ctx.unique_name("sim2real-behav-proj-cache-")
    token = ctx.unique_name("sim2real-token-")
    _create_project(cb, ctx, name, role, buildspec,
                    cache={"type": "S3", "location": f"{bucket}/cache"})

    def _one_build():
        started = _start_build_with_stop_registered(
            cb, ctx, projectName=name,
            environmentVariablesOverride=[
                {"name": "SIM2REAL_TOKEN", "value": token, "type": "PLAINTEXT"}])
        final = _poll_build_terminal(cb, started["id"], timeout_s=240)
        assert final is not None, f"build {started['id']!r} never reported buildComplete"
        exported = dict((v["name"], v["value"])
                        for v in final.get("exportedEnvironmentVariables", []))
        return final, exported

    first, exp1 = _one_build()
    assert first["buildStatus"] == "SUCCEEDED", (
        f"the first build was {first['buildStatus']!r}; phases={_phases(first)!r}"
    )
    assert exp1.get("SIM2REAL_CACHE_STATE") == "miss", (
        f"the first build of a fresh project must miss the cache, exported {exp1!r}"
    )
    warmed = _poll_keys(s3, bucket, "cache/", True, timeout_s=90)
    assert warmed, (
        f"the service uploaded no cache object under s3://{bucket}/cache/ after a build that "
        f"declared cache.paths; the whole bucket holds {_list_keys(s3, bucket)!r}"
    )

    second, exp2 = _one_build()
    assert second["buildStatus"] == "SUCCEEDED", (
        f"the second build was {second['buildStatus']!r}; phases={_phases(second)!r}"
    )
    assert exp2.get("SIM2REAL_CACHE_STATE") == "hit", (
        f"the second build must read the cache the first one warmed, exported {exp2!r}; "
        f"the cache objects in S3 were {warmed!r}"
    )
    assert exp2.get("SIM2REAL_CACHE_VALUE") == token, (
        f"build 2 read {exp2.get('SIM2REAL_CACHE_VALUE')!r} out of the cache, expected the "
        f"token build 1 wrote, {token!r}"
    )

    cb.invalidate_project_cache(projectName=name)
    # Invalidation is bookkeeping, not a delete: the S3 cache object stays, but the next
    # build stops restoring it.
    remaining = _list_keys(s3, bucket, "cache/")
    assert remaining == warmed, (
        f"InvalidateProjectCache should leave the S3 cache objects untouched, they went "
        f"{warmed!r} -> {remaining!r}"
    )

    third, exp3 = _one_build()
    assert third["buildStatus"] == "SUCCEEDED", (
        f"the third build was {third['buildStatus']!r}; phases={_phases(third)!r}"
    )
    assert exp3.get("SIM2REAL_CACHE_STATE") == "miss", (
        f"build 3 still saw the cache after InvalidateProjectCache: {exp3!r}"
    )
    assert len({first["id"], second["id"], third["id"]}) == 3, (
        f"expected three distinct build ids, got "
        f"{[first['id'], second['id'], third['id']]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
