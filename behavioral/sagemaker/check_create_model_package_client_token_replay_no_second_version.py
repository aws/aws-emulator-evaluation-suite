"""create-model-package-client-token-replay-no-second-version."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-model-package-client-token-replay-no-second-version"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']


# ===== helpers (self-contained) =====

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an
    over-permissive target is never mistaken for a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(
        f"reusing a spent ClientToken SUCCEEDED (over-permissive) -- a retried registration "
        f"would silently add a registry version: {result!r}"
    )


def _poll(fn, pred, *, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _inference_spec(ctx, content_type="text/csv"):
    """Registration-only InferenceSpecification -- nothing is pulled or run, so no
    billable resource is created.

    Real AWS DOES validate ECR image
    reachability at CreateModelPackage time -- without `SkipModelValidation='All'` this
    exact spec is refused with ValidationException / "Access denied for registry ID:
    123456789012 ... Please check if your ECR image exists and has proper pull permissions
    for SageMaker." Every call in this check passes SkipModelValidation='All', which makes
    the placeholder image acceptable, so no ECR repository has to be minted.
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
        "SupportedContentTypes": [content_type],
    }


def _delete_group_when_empty(sm, group, timeout_s=180, interval_s=10):
    """Delete a model package group, retrying while its versions are still draining.

    DeleteModelPackage is not instantaneous and DeleteModelPackageGroup is refused with
    "... still contains Model Packages." until every version is gone. Without
    the retry the group and its versions would leak.
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


def _versions(sm, group):
    return sorted(
        s["ModelPackageVersion"]
        for s in sm.list_model_packages(
            ModelPackageGroupName=group, MaxResults=100
        )["ModelPackageSummaryList"]
    )
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CreateModelPackage ClientToken is single-use and account-scoped: a verbatim replay, a changed
    body and a different group are each refused with ConflictException and its exact message, and
    no reuse mints a second version, while a fresh token registers version 2.
    """
    sm = ctx.client("sagemaker")
    timeout_s = 180
    group = ctx.unique_name("sim2real-behav-mpg-")
    sm.create_model_package_group(ModelPackageGroupName=group)
    # First registered => last deleted (LIFO): the group cannot go before its
    # versions.
    ctx.on_cleanup(lambda: _delete_group_when_empty(sm, group))

    # ClientToken is 1-36 chars, ^[a-zA-Z0-9-]+$ -- real AWS enforces the 36-char ceiling
    # with ValidationException / "... at 'clientToken' failed to satisfy constraint: Member
    # must have length less than or equal to 36", so the prefix stays short.
    token = ctx.unique_name("tok-")
    assert len(token) <= 36, f"ClientToken {token!r} exceeds the modeled 36-char maximum"
    body = {
        "ModelPackageGroupName": group,
        "ModelPackageDescription": "idempotency fixture",
        "InferenceSpecification": _inference_spec(ctx),
        "SkipModelValidation": "All",
        "ClientToken": token,
    }
    first = sm.create_model_package(**body)["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=first))
    desc = _poll(
        lambda: sm.describe_model_package(ModelPackageName=first),
        lambda d: d["ModelPackageStatus"] in ("Completed", "Failed"),
        timeout_s=timeout_s,
    )
    assert desc["ModelPackageStatus"] == "Completed", desc["ModelPackageStatus"]
    assert desc["ModelPackageVersion"] == 1, desc

    def _reuse_message(named_group):
        """The refusal names the group carried by the REJECTED request, not the group the
        token was first spent on -- which is how the token's account-wide scope is visible
        from the message alone."""
        return (
            "Specified idempotent client token in Model package with Group:%s was used "
            "with different request parameters within the idempotency window."
            % named_group
        )

    def _assert_reuse_refused(fn, named_group, what):
        code, message = _error(fn)
        assert code == "ConflictException", (
            f"{what}: expected ConflictException, got code={code!r} message={message!r}"
        )
        assert message == _reuse_message(named_group), (
            f"{what}: the refusal must name the spent token's idempotency window and the "
            f"group the request carried; expected {_reuse_message(named_group)!r}, got "
            f"{message!r}"
        )

    # ---- break exactly one thing, #1: replay the SAME token with a byte-identical body.
    # Real AWS refuses this rather than returning the first ARN (see the docstring).
    _assert_reuse_refused(
        lambda: sm.create_model_package(**body), group,
        "byte-identical replay with the same ClientToken",
    )
    assert _versions(sm, group) == [1], (
        f"ClientToken replay created a second version: {_versions(sm, group)}"
    )
    unchanged = sm.describe_model_package(ModelPackageName=first)
    assert unchanged["ModelPackageArn"] == first, unchanged
    assert unchanged["ModelPackageDescription"] == "idempotency fixture", (
        f"the refused replay mutated version 1's description: "
        f"{unchanged.get('ModelPackageDescription')!r}"
    )

    # ---- break exactly one thing, #2: the SAME token with a genuinely different body.
    _assert_reuse_refused(
        lambda: sm.create_model_package(
            **dict(
                body,
                ModelPackageDescription="different body, same token",
                InferenceSpecification=_inference_spec(
                    ctx, content_type="application/json"
                ),
            )
        ),
        group,
        "changed body with the same ClientToken",
    )
    assert _versions(sm, group) == [1], (
        f"token reuse with a changed body still created a version: "
        f"{_versions(sm, group)}"
    )
    assert sm.describe_model_package(ModelPackageName=first)[
        "ModelPackageDescription"
    ] == "idempotency fixture", (
        "the refused changed-body reuse overwrote version 1 in place"
    )

    # ---- break exactly one thing, #3: the SAME token against a DIFFERENT group. The token
    # is account-scoped, so this is refused too -- and the message names the SECOND group,
    # proving the scope is not per-group. An emulator that keys its idempotency table on
    # (group, token) accepts this call and mints a version in the second group.
    other_group = ctx.unique_name("sim2real-behav-mpg-other-")
    sm.create_model_package_group(ModelPackageGroupName=other_group)
    ctx.on_cleanup(lambda: _delete_group_when_empty(sm, other_group))
    _assert_reuse_refused(
        lambda: sm.create_model_package(
            **dict(body, ModelPackageGroupName=other_group)
        ),
        other_group,
        "the same ClientToken against a different group",
    )
    assert _versions(sm, other_group) == [], (
        f"the account-scoped token was accepted for a second group: "
        f"{_versions(sm, other_group)}"
    )
    assert _versions(sm, group) == [1], (
        f"the cross-group reuse mutated the first group: {_versions(sm, group)}"
    )

    # ---- control: a FRESH token on the same group does create version 2, proving the
    # refusals above were token-scoped and not a blanket refusal to register.
    fresh_token = ctx.unique_name("tok-")
    assert fresh_token != token, (
        f"fresh ClientToken collided with the spent one: {fresh_token!r} == {token!r}"
    )
    second = sm.create_model_package(
        **dict(body, ClientToken=fresh_token)
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=second))
    assert second != first, f"fresh token returned the first ARN: {second}"
    assert second.endswith("/2"), (
        f"the control registration must be version 2 of the same group: {second}"
    )
    got = _poll(
        lambda: _versions(sm, group),
        lambda vs: vs == [1, 2],
        timeout_s=timeout_s,
    )
    assert got == [1, 2], f"control registration did not yield version 2: {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
