"""create-model-package-concurrent-version-assignment."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-package-concurrent-version-assignment"
GROUP = "concurrency"
SERVICES = ["sagemaker"]

_N = 6


# ===== helpers =====
# DeleteModelPackage is not instantaneous, and DeleteModelPackageGroup is refused with
# ValidationException / "... still contains Model Packages." until every version is gone.
# Deleting the group right after issuing the version deletes races that
# drain and leaks the group.
def _delete_group_when_empty(sm, group, timeout_s=180, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_model_package_group(ModelPackageGroupName=group)
            return
        except ClientError as exc:
            message = (exc.response.get("Error", {}).get("Message") or "").lower()
            if "not found" in message or "does not exist" in message:
                return
            if "still contains model packages" not in message:
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateModelPackage calls into one ModelPackageGroup get unique, contiguous
    ModelPackageVersion numbers 1..N, confirmed by an independent ListModelPackages read; a caller
    that loses the version-counter race gets ConflictException and retries its own call."""
    sm = ctx.client("sagemaker")

    group_name = ctx.unique_name("sim2real-behav-mpg-")
    sm.create_model_package_group(ModelPackageGroupName=group_name)

    created_arns: list[str] = []

    def _cleanup_group():
        for arn in created_arns:
            try:
                sm.delete_model_package(ModelPackageName=arn)
            except ClientError as exc:
                error = exc.response.get("Error", {})
                if error.get("Code") != "ValidationException" or "does not exist" not in error.get("Message", ""):
                    raise
        _delete_group_when_empty(sm, group_name)

    ctx.on_cleanup(_cleanup_group)

    # CreateModelPackage refuses an unreachable ECR image with ValidationException / "Access
    # denied for registry ID: ..." unless SkipModelValidation="All", which would refuse every
    # concurrent call below before version assignment is exercised.
    image = f"000000000000.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-behav-nonexistent:latest"
    barrier = threading.Barrier(_N)

    def _create(_index: int) -> str:
        barrier.wait()
        # Bounded retry on the version-counter race (see docstring): a losing caller gets
        # ConflictException and must retry its own call, never a different one, and never
        # unconditionally -- any other error propagates immediately.
        deadline = time.monotonic() + 60
        while True:
            try:
                resp = sm.create_model_package(
                    ModelPackageGroupName=group_name,
                    InferenceSpecification={
                        "Containers": [{"Image": image}],
                        "SupportedContentTypes": ["text/csv"],
                        "SupportedResponseMIMETypes": ["text/csv"],
                    },
                    SkipModelValidation="All",
                )
                return resp["ModelPackageArn"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ConflictException":
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)

    with ThreadPoolExecutor(max_workers=_N) as pool:
        arns = [f.result() for f in [pool.submit(_create, i) for i in range(_N)]]
    created_arns.extend(arns)

    assert len(set(arns)) == _N, f"expected {_N} distinct ARNs, got {arns}"
    versions = sorted(int(arn.rsplit("/", 1)[-1]) for arn in arns)
    assert versions == list(range(1, _N + 1)), (
        f"expected versions 1..{_N} assigned with no collision/gap, got {versions}"
    )

    # Independent read at the destination: ListModelPackages, a different operation than
    # the CreateModelPackage calls that mutated, must report the same distinct/contiguous
    # 1..N versions -- not merely what the mutating responses themselves claimed.
    listed = sm.list_model_packages(
        ModelPackageGroupName=group_name, MaxResults=100,
        SortBy="CreationTime", SortOrder="Ascending",
    )["ModelPackageSummaryList"]
    listed_arns = sorted(s["ModelPackageArn"] for s in listed)
    listed_versions = sorted(s["ModelPackageVersion"] for s in listed)
    assert listed_arns == sorted(arns), (
        f"ListModelPackages (independent read) disagrees with the CreateModelPackage "
        f"responses: listed {listed_arns}, created {sorted(arns)}"
    )
    assert listed_versions == list(range(1, _N + 1)), (
        f"ListModelPackages (independent read) shows versions {listed_versions}, expected "
        f"a dense 1..{_N} run with no collision/gap"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
