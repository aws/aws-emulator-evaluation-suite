"""list-builds-for-project-default-sort-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-builds-for-project-default-sort-order"
GROUP = "ordering"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListBuildsForProject defaults to DESCENDING-by-build-number order and honors an explicit sortOrder."""
    role_arn = _create_minimal_codebuild_role(ctx)
    cb = ctx.client("codebuild")
    project_name = ctx.unique_name("sim2real-cb-proj-")
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-marker\n"
    _create_no_source_project(ctx, cb, project_name, role_arn, buildspec)

    # buildNumber is assigned in call order, so build_id_1 has the lower
    # build number and build_id_2 the higher one.
    build_id_1 = _start_build(ctx, cb, project_name)
    build_id_2 = _start_build(ctx, cb, project_name)
    assert build_id_1 != build_id_2, f"start_build returned the same id twice: {build_id_1!r}"

    default_ids = _poll_until(
        lambda: cb.list_builds_for_project(projectName=project_name)["ids"],
        lambda ids: build_id_1 in ids and build_id_2 in ids,
        timeout_s=60.0,
        interval_s=3.0,
    )
    asc_ids = cb.list_builds_for_project(projectName=project_name, sortOrder="ASCENDING")["ids"]
    desc_ids = cb.list_builds_for_project(projectName=project_name, sortOrder="DESCENDING")["ids"]

    assert set(default_ids) == {build_id_1, build_id_2}, (
        f"expected exactly {{build_id_1, build_id_2}}, got {default_ids}"
    )
    # Docs: "If [sortOrder] is not specified, the results are sorted in
    # descending order" (by build number) -- default must equal explicit DESCENDING.
    assert default_ids == desc_ids, f"default order {default_ids} must equal explicit DESCENDING {desc_ids}"
    assert default_ids[0] == build_id_2 and default_ids[1] == build_id_1, (
        f"expected higher-build-number build ({build_id_2}) first, got {default_ids}"
    )

    # ASCENDING must be the exact reverse of DESCENDING.
    assert asc_ids == list(reversed(desc_ids)), f"ASCENDING {asc_ids} must reverse DESCENDING {desc_ids}"
    assert asc_ids[0] == build_id_1 and asc_ids[1] == build_id_2, (
        f"expected lower-build-number build ({build_id_1}) first, got {asc_ids}"
    )


# ===== helpers =====

def _create_minimal_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_no_source_project(ctx, cb, project_name: str, role_arn: str, buildspec: str) -> None:
    # A freshly created IAM role needs a few seconds to propagate before
    # CodeBuild can reliably assume it; retry the create on the transient
    # InvalidInputException real AWS raises during that window instead of
    # guessing a fixed delay.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            cb.create_project(
                name=project_name,
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
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise

    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _start_build(ctx, cb, project_name: str) -> str:
    build_id = cb.start_build(projectName=project_name)["build"]["id"]

    def _cleanup():
        try:
            cb.stop_build(id=build_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        cb.batch_delete_builds(ids=[build_id])

    ctx.on_cleanup(_cleanup)
    return build_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
