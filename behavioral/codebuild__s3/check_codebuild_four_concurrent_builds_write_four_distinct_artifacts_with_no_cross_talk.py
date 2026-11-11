"""codebuild-four-concurrent-builds-write-four-distinct-artifacts-with-no-cross-talk."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor


from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====

_SCENARIO = "codebuild-concurrent-artifacts"
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


_BUILD_TIMEOUT_S = 240.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_builds_terminal(cb, build_ids, *, timeout_s, interval_s=2.0):
    """Poll BatchGetBuilds until every build is complete; an id maps to None if still running."""
    deadline = time.monotonic() + timeout_s
    done = {}
    while True:
        pending = [b for b in build_ids if b not in done]
        got = cb.batch_get_builds(ids=pending)
        by_id = {b["id"]: b for b in got.get("builds", [])}
        lost = [b for b in pending if b not in by_id]
        assert not lost, f"BatchGetBuilds lost build(s) {lost!r}: {got!r}"
        for build_id in pending:
            if by_id[build_id].get("buildComplete") is True:
                done[build_id] = by_id[build_id]
        if len(done) == len(build_ids):
            return done
        if time.monotonic() >= deadline:
            return {b: done.get(b) for b in build_ids}
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]

# ===== check =====

CHECK = "codebuild-four-concurrent-builds-write-four-distinct-artifacts-with-no-cross-talk"
GROUP = 'concurrency'
SERVICES = ['codebuild', 's3']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Four concurrent builds of one project, each given its own seed, all succeed and each writes
    its own S3 artifact holding exactly its own computed value, with no cross-talk.
    """
    cb = ctx.client("codebuild")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cb-conc-").lower().replace("_", "-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["s3:PutObject", "s3:GetObject", "s3:GetBucketAcl",
                    "s3:GetBucketLocation", "s3:ListBucket"],
         "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
    ])

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        '      - printf \'%s\' "$(( SIM2REAL_SEED * 7 + 3 ))" > artifact.txt\n'
        "artifacts:\n"
        "  files:\n"
        "    - artifact.txt\n"
    )

    name = ctx.unique_name("sim2real-behav-proj-conc-")
    _create_project(
        cb, ctx, name, role, buildspec, concurrentBuildLimit=4,
        artifacts={"type": "S3", "location": bucket, "path": "out", "name": "build",
                   "namespaceType": "BUILD_ID", "packaging": "NONE",
                   "encryptionDisabled": True},
    )

    seeds = [1000 + 137 * i + (abs(hash(name)) % 50) for i in range(4)]
    assert len(set(seeds)) == 4, f"the four seeds must be distinct, got {seeds!r}"

    def _start(seed):
        return seed, _start_build_with_stop_registered(
            cb, ctx, projectName=name,
            environmentVariablesOverride=[
                {"name": "SIM2REAL_SEED", "value": str(seed), "type": "PLAINTEXT"}],
        )["id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        started = list(pool.map(_start, seeds))

    seed_by_id = dict((bid, seed) for seed, bid in started)
    build_ids = [bid for _, bid in started]
    assert len(set(build_ids)) == 4, (
        f"expected 4 distinct build ids, got {build_ids!r}"
    )

    finals = _poll_builds_terminal(cb, build_ids, timeout_s=_budget_s(ctx, _BUILD_TIMEOUT_S))
    if None in finals.values() and _budget_spent(ctx):
        raise TimeoutError("the four builds reporting buildComplete: the run budget ended first; not graded")
    for bid in build_ids:
        assert finals[bid] is not None, f"build {bid!r} never reported buildComplete"

    statuses = set(f["buildStatus"] for f in finals.values())
    assert statuses == {"SUCCEEDED"}, (
        f"concurrent build statuses were {sorted(statuses)!r}; phases="
        f"{dict((b, _phases(f)) for b, f in finals.items())!r}"
    )

    all_keys = _list_keys(s3, bucket)
    per_build = {}
    keys_seen = []
    for bid in build_ids:
        uuid = bid.split(":")[-1]
        mine = [k for k in all_keys if uuid in k]
        assert len(mine) == 1, (
            f"build {bid!r} should own exactly one artifact key, owns {mine!r}; every key "
            f"in the bucket: {all_keys!r}"
        )
        keys_seen.append(mine[0])
        per_build[bid] = s3.get_object(Bucket=bucket, Key=mine[0])["Body"].read()

    assert len(set(keys_seen)) == 4, (
        f"expected 4 distinct artifact keys, got {sorted(keys_seen)!r}"
    )
    expected_per_build = dict(
        (bid, str(seed_by_id[bid] * 7 + 3).encode()) for bid in build_ids)
    assert per_build == expected_per_build, (
        f"artifact contents crossed builds: got {per_build!r}, expected "
        f"{expected_per_build!r}"
    )
    assert all(len(v) > 0 for v in per_build.values()), (
        f"an artifact was empty or truncated: {per_build!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
