"""start-build-image-and-compute-overrides-apply-to-that-build-only."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-build-image-and-compute-overrides-apply-to-that-build-only"
GROUP = "overrides"
SERVICES = ["codebuild"]

_PROJECT_IMAGE = "aws/codebuild/standard:7.0"
_PROJECT_COMPUTE = "BUILD_GENERAL1_SMALL"
_PROJECT_TIMEOUT = 60
_OVERRIDE_IMAGE = "aws/codebuild/amazonlinux-x86_64-standard:5.0"
_OVERRIDE_COMPUTE = "BUILD_GENERAL1_MEDIUM"
_OVERRIDE_TIMEOUT = 5

# The build reports the image it ran in and the distribution of that image's root filesystem.
_BUILDSPEC = (
    "version: 0.2\n"
    "env:\n"
    "  exported-variables:\n"
    "    - SIM2REAL_IMAGE\n"
    "    - SIM2REAL_OS\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    '      - export SIM2REAL_IMAGE="$CODEBUILD_BUILD_IMAGE"\n'
    '      - export SIM2REAL_OS="$(. /etc/os-release && echo $ID)"\n'
    '      - echo "sim2real ran in $SIM2REAL_IMAGE on $SIM2REAL_OS"\n'
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


def _create_role(ctx, iam) -> str:
    """A CodeBuild service role that may write logs; returns its ARN."""
    name = ctx.unique_name("sim2real-behav-cb-ovr-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, Path="/sim2real/",
                          AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": "codebuild-overrides"}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Resource": "*",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"),
                             "NoSuchEntity"))
    return arn


def _create_project(ctx, cb, name: str, role: str) -> dict:
    """CreateProject, retrying while the new role's trust policy propagates (IAM exposes no
    condition to poll); the retry is bounded and keyed on the propagation message."""
    deadline = time.monotonic() + 90
    while True:
        try:
            project = cb.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
                artifacts={"type": "NO_ARTIFACTS"},
                cache={"type": "NO_CACHE"},
                environment={"type": "LINUX_CONTAINER", "image": _PROJECT_IMAGE,
                             "computeType": _PROJECT_COMPUTE},
                serviceRole=role,
                timeoutInMinutes=_PROJECT_TIMEOUT,
                logsConfig={"cloudWatchLogs": {"status": "DISABLED"},
                            "s3Logs": {"status": "DISABLED"}},
                tags=[{"key": "sim2real", "value": "codebuild-overrides"}],
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


def _env(build: dict) -> tuple:
    env = build.get("environment", {})
    return env.get("image"), env.get("computeType"), build.get("timeoutInMinutes")


def _exported(build: dict) -> dict:
    return {v["name"]: v.get("value") for v in build.get("exportedEnvironmentVariables", [])}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """StartBuild's image, compute-type and timeout overrides apply to that build only: its buildspec runs
    in the override image, while a later plain build uses the project's settings and the project is
    unchanged."""
    cb = ctx.client("codebuild")
    iam = ctx.client("iam")
    role = _create_role(ctx, iam)
    name = ctx.unique_name("sim2real-behav-cb-ovr-")
    _create_project(ctx, cb, name, role)

    overridden = _start(ctx, cb, projectName=name, imageOverride=_OVERRIDE_IMAGE,
                        computeTypeOverride=_OVERRIDE_COMPUTE,
                        timeoutInMinutesOverride=_OVERRIDE_TIMEOUT)
    assert _env(overridden) == (_OVERRIDE_IMAGE, _OVERRIDE_COMPUTE, _OVERRIDE_TIMEOUT), (
        f"StartBuild answered (image, computeType, timeout) {_env(overridden)!r}, expected the "
        f"overrides {(_OVERRIDE_IMAGE, _OVERRIDE_COMPUTE, _OVERRIDE_TIMEOUT)!r}"
    )
    plain = _start(ctx, cb, projectName=name)
    assert _env(plain) == (_PROJECT_IMAGE, _PROJECT_COMPUTE, _PROJECT_TIMEOUT), (
        f"a build started without overrides answered {_env(plain)!r}, expected the project's "
        f"{(_PROJECT_IMAGE, _PROJECT_COMPUTE, _PROJECT_TIMEOUT)!r}"
    )

    done_overridden = _until_complete(cb, overridden["id"])
    done_plain = _until_complete(cb, plain["id"])
    for label, build in (("overridden", done_overridden), ("plain", done_plain)):
        assert build["buildStatus"] == "SUCCEEDED", (
            f"the {label} build ended {build['buildStatus']!r}; phases "
            f"{[(p.get('phaseType'), p.get('phaseStatus')) for p in build.get('phases', [])]!r}"
        )

    assert _env(done_overridden) == (_OVERRIDE_IMAGE, _OVERRIDE_COMPUTE, _OVERRIDE_TIMEOUT), (
        f"the completed overridden build records {_env(done_overridden)!r}"
    )
    assert _exported(done_overridden) == {"SIM2REAL_IMAGE": _OVERRIDE_IMAGE, "SIM2REAL_OS": "amzn"}, (
        f"the overridden build's buildspec reported {_exported(done_overridden)!r}; it must run "
        f"in {_OVERRIDE_IMAGE!r}, an Amazon Linux image"
    )
    assert _env(done_plain) == (_PROJECT_IMAGE, _PROJECT_COMPUTE, _PROJECT_TIMEOUT), (
        f"the completed plain build records {_env(done_plain)!r}"
    )
    assert _exported(done_plain) == {"SIM2REAL_IMAGE": _PROJECT_IMAGE, "SIM2REAL_OS": "ubuntu"}, (
        f"the plain build's buildspec reported {_exported(done_plain)!r}; it must run in the "
        f"project's {_PROJECT_IMAGE!r}, an Ubuntu image"
    )

    projects = cb.batch_get_projects(names=[name])["projects"]
    assert len(projects) == 1, f"BatchGetProjects returned {len(projects)} projects"
    env = projects[0]["environment"]
    kept = (env.get("image"), env.get("computeType"), projects[0].get("timeoutInMinutes"))
    assert kept == (_PROJECT_IMAGE, _PROJECT_COMPUTE, _PROJECT_TIMEOUT), (
        f"the project now reads (image, computeType, timeout) {kept!r}; overrides must not be "
        f"written back to it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
