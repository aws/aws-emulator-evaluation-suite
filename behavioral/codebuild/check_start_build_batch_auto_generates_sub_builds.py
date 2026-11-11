"""start-build-batch-auto-generates-sub-builds."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-build-batch-auto-generates-sub-builds"
GROUP = "server-side"
SERVICES = ["codebuild"]

_BATCH_BUILDSPEC = (
    "version: 0.2\n"
    "batch:\n"
    "  fast-fail: false\n"
    "  build-list:\n"
    "    - identifier: build1\n"
    "    - identifier: build2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo sub-build-ok\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBuildBatch autonomously creates & orchestrates sub-builds with no further client action."""
    codebuild = ctx.client("codebuild")
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(
        ctx,
        role_arn,
        _BATCH_BUILDSPEC,
        extra={
            "buildBatchConfig": {
                "serviceRole": role_arn,
                "combineArtifacts": False,
            }
        },
    )

    batch = codebuild.start_build_batch(projectName=project_name)["buildBatch"]
    batch_id = batch["id"]
    ctx.on_cleanup(lambda: _stop_batch(codebuild, batch_id))

    def _sub_builds_created():
        got = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"][0]
        groups = got.get("buildGroups", [])
        if len(groups) >= 2 and all(g.get("currentBuildSummary", {}).get("arn") for g in groups):
            return groups
        return None

    groups = _poll_until(_sub_builds_created, timeout_s=180, interval_s=5)
    assert groups is not None, "service never auto-created the two build-list sub-builds"
    identifiers = {g.get("identifier") for g in groups}
    # The two configured build-list identifiers must both appear as real, independently
    # orchestrated sub-builds. Some accounts/regions also surface an implicit wrapper group
    # (e.g. identifier=None) alongside the two named ones, so assert a superset rather than
    # an exact set to avoid coupling to that unrelated detail.
    assert {"build1", "build2"}.issubset(identifiers), f"expected build1/build2 in {identifiers!r}"
    named_groups = [g for g in groups if g.get("identifier") in ("build1", "build2")]
    sub_build_arns = [g["currentBuildSummary"]["arn"] for g in named_groups]
    assert len(set(sub_build_arns)) == 2, "sub-builds should be distinct build resources"

    # The individual sub-build is a real, independently retrievable Build resource.
    got_builds = codebuild.batch_get_builds(ids=sub_build_arns)
    assert len(got_builds["builds"]) == 2, (
        f"expected 2 independently retrievable sub-builds for {sub_build_arns!r}, "
        f"got {got_builds['builds']!r}"
    )
    assert all(b["projectName"] == project_name for b in got_builds["builds"]), (
        f"expected every sub-build to belong to {project_name!r}, "
        f"got projectNames {[b['projectName'] for b in got_builds['builds']]!r}"
    )

    def _batch_listed():
        token = None
        for _ in range(20):
            kwargs = {"maxResults": 100}
            if token:
                kwargs["nextToken"] = token
            page = codebuild.list_build_batches(**kwargs)
            if batch_id in page.get("ids", []):
                return True
            token = page.get("nextToken")
            if not token:
                break
        return None

    found = _poll_until(_batch_listed, timeout_s=60, interval_s=5)
    assert found, "batch id never appeared in ListBuildBatches"


# ===== helpers =====
def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _stop_batch(codebuild, batch_id: str) -> None:
    """Teardown: stops the batch unless it already completed; any failure raises."""
    batches = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"]
    if batches and not batches[0].get("complete"):
        codebuild.stop_build_batch(id=batch_id)


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if value is not None:
            return value
        time.sleep(interval_s)
    return None


def _make_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        _try(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
        _try(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "s3:*",
                    "ssmmessages:*",
                    "ssm:StartSession",
                    "codebuild:*",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return role_arn


def _create_no_source_project(
    ctx, role_arn: str, buildspec: str, extra: dict[str, Any] | None = None
) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    kwargs: dict[str, Any] = dict(
        name=name,
        source={"type": "NO_SOURCE", "buildspec": buildspec},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    if extra:
        kwargs.update(extra)

    from botocore.exceptions import ClientError

    # A freshly created role/policy is not always immediately visible to CodeBuild;
    # it manifests as InvalidInputException on the service-role check, so bounded
    # retry here also absorbs that IAM propagation delay (no separate sleep needed).
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(5)
                continue
            raise
    else:
        assert last_err is not None
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
