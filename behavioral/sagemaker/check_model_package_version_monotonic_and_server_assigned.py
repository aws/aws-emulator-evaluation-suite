"""model-package-version-monotonic-and-server-assigned."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-version-monotonic-and-server-assigned"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']


# ===== helpers (self-contained) =====

def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, so a
    target accepting what AWS refuses is not mistaken for a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_group_when_empty(sm, group, timeout_s=180, interval_s=10):
    """Delete a model package group, retrying while its versions are still draining.

    DeleteModelPackage is not instantaneous, and DeleteModelPackageGroup is refused with
    ValidationException / "... still contains Model Packages." until every version is gone.
    Without the retry the group -- and the versions
    under it -- would leak.
    """
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


def _poll(fn, pred, *, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _inference_spec(ctx):
    """A syntactically valid, registration-only InferenceSpecification.

    Model *registration* stores the ECR path; nothing is pulled or run until an
    endpoint/transform job is created, so this creates no billable resource and
    needs no real image.
    """
    return {
        "Containers": [
            {
                "Image": (
                    "123456789012.dkr.ecr.%s.amazonaws.com/"
                    "sim2real-behav-inference:latest" % ctx.region
                ),
            }
        ],
        "SupportedContentTypes": ["text/csv"],
        "SupportedResponseMIMETypes": ["text/csv"],
    }


def _create_model_package_group(ctx, name=None):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-mpg-")
    arn = sm.create_model_package_group(
        ModelPackageGroupName=name,
        ModelPackageGroupDescription="behav registry group",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["ModelPackageGroupArn"]
    # Registered FIRST so LIFO cleanup deletes it LAST -- DeleteModelPackageGroup
    # is refused while any version still exists.
    ctx.on_cleanup(lambda: _delete_group_when_empty(sm, name))
    return name, arn


def _register_version(ctx, group, **extra):
    sm = ctx.client("sagemaker")
    kwargs = {
        "ModelPackageGroupName": group,
        "ModelPackageDescription": "behav model version",
        "InferenceSpecification": _inference_spec(ctx),
        "SkipModelValidation": "All",
    }
    kwargs.update(extra)
    arn = sm.create_model_package(**kwargs)["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=arn))
    return arn


def _wait_terminal(ctx, arn, *, timeout_s):
    sm = ctx.client("sagemaker")
    desc = _poll(
        lambda: sm.describe_model_package(ModelPackageName=arn),
        lambda d: d["ModelPackageStatus"] in ("Completed", "Failed"),
        timeout_s=timeout_s,
    )
    assert desc["ModelPackageStatus"] == "Completed", (
        f"model package {arn} did not reach Completed: {desc['ModelPackageStatus']} "
        f"{desc.get('ModelPackageStatusDetails')}"
    )
    return desc
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registry versions are server-assigned 1, 2, 3 per group, matching the ARN suffix; a versioned
    package has NO independent name: Describe omits ModelPackageName, the group/N shorthand and
    ModelPackageName plus ModelPackageGroupName are each refused with ValidationException.
    """
    sm = ctx.client("sagemaker")
    timeout_s = 180
    group, group_arn = _create_model_package_group(ctx)

    arns = [_register_version(ctx, group) for _ in range(3)]
    assert len(set(arns)) == 3, f"registrations collided: {arns}"

    versions = []
    for expected, arn in enumerate(arns, start=1):
        desc = _wait_terminal(ctx, arn, timeout_s=timeout_s)
        versions.append(desc["ModelPackageVersion"])
        assert desc["ModelPackageVersion"] == expected, (
            f"registration #{expected} got version {desc['ModelPackageVersion']} "
            f"(arn {arn})"
        )
        assert arn.endswith(f"/{expected}"), (
            f"ARN does not carry the version suffix: {arn} (version {expected})"
        )
        assert desc["ModelPackageGroupName"] == group, desc
        assert desc["ModelPackageArn"] == arn, desc
        # A versioned model package has no independent name; it is group + version, and
        # DescribeModelPackage OMITS ModelPackageName rather than echoing the group there.
        assert "ModelPackageName" not in desc, (
            f"a versioned model package has no independent name, so DescribeModelPackage "
            f"must omit ModelPackageName entirely; version {expected} returned "
            f"ModelPackageName={desc.get('ModelPackageName')!r}"
        )

    assert versions == [1, 2, 3], f"versions not dense/monotonic: {versions}"

    # The "no independent name" rule holds on the INPUT side too: the two identity modes --
    # a standalone ModelPackageName, or a group plus a server-assigned version -- are
    # mutually exclusive, and naming both is refused. (CreateModelPackage has no
    # ModelPackageVersion input member at all, so a caller can never request a version;
    # that is a modelled fact rather than a service behaviour, so it is stated here and not
    # asserted.)
    code, message = _error(
        lambda: sm.create_model_package(
            ModelPackageName=ctx.unique_name("sim2real-behav-mp-"),
            ModelPackageGroupName=group,
            InferenceSpecification=_inference_spec(ctx),
            SkipModelValidation="All",
        )
    )
    assert code == "ValidationException", (
        f"CreateModelPackage naming BOTH a standalone package name and a group must be "
        f"refused -- the two identity modes are mutually exclusive -- got code={code!r} "
        f"message={message!r}"
    )
    assert message == (
        "Both ModelPackageName and ModelPackageGroupName are provided in the input. "
        "Cannot determine which one to use."
    ), (
        f"the refusal must state that the two identity modes conflict; got {message!r}"
    )
    # Effect absent: the refused create added no fourth version.
    after_reject = sorted(
        s["ModelPackageVersion"]
        for s in sm.list_model_packages(
            ModelPackageGroupName=group, MaxResults=100
        )["ModelPackageSummaryList"]
    )
    assert after_reject == [1, 2, 3], (
        f"the refused CreateModelPackage still registered a version: group now holds "
        f"{after_reject}, expected [1, 2, 3]"
    )

    # The FULL ARN is the only addressing form for a version: it resolves to exactly that
    # version, and the `group/N` shorthand does NOT.
    by_arn = sm.describe_model_package(ModelPackageName=arns[1])
    assert by_arn["ModelPackageVersion"] == 2, by_arn
    assert by_arn["ModelPackageArn"] == arns[1], by_arn
    assert by_arn["ModelPackageGroupName"] == group, by_arn
    shorthand = f"{group}/2"
    code_ref, message_ref = _error(
        lambda: sm.describe_model_package(ModelPackageName=shorthand)
    )
    assert code_ref == "ValidationException", (
        f"DescribeModelPackage({shorthand!r}) returned code={code_ref!r}; the "
        f"`group/N` shorthand is not an accepted identifier at the API and must be "
        f"refused, not resolved (message={message_ref!r})"
    )
    assert message_ref == (
        "1 validation error detected: Value '%s' at 'modelPackageName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "^[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}$" % shorthand
    ), (
        f"the refusal must be the modelPackageName pattern constraint (which forbids the "
        f"'/' in the shorthand) and must quote the rejected value; got {message_ref!r}"
    )

    # The version projection in List* must agree with Describe, and must not
    # renumber.
    listed = sm.list_model_packages(
        ModelPackageGroupName=group, MaxResults=100, SortBy="CreationTime",
        SortOrder="Ascending",
    )["ModelPackageSummaryList"]
    got = [s["ModelPackageVersion"] for s in listed]
    assert sorted(got) == [1, 2, 3], f"group {group} versions listed as: {got}"
    assert [s["ModelPackageArn"] for s in listed if s["ModelPackageVersion"] == 3] == [
        arns[2]
    ], listed
    assert group_arn.endswith(group), group_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
