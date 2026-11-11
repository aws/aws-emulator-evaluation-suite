"""rejects-changeset-for-versionless-application."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-changeset-for-versionless-application"
GROUP = 'deploy-sar-changeset'
SERVICES = ['cloudformation', 'serverlessrepo', 'sqs']

_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Q:
    Type: AWS::SQS::Queue
"""

# ===== helpers =====

# SAR's read path is eventually consistent while its write path is not: CreateApplicationVersion
# returns the version synchronously, but GetApplication took several seconds to serve it. The
# positive control below has to wait for that, or it races SAR's replication and reports the
# consistency lag as a rejection.
_CONSISTENCY_BUDGET_S = 120.0


_NO_VERSION_CHANGE_SET = "Can't create cloudformation changeset from application with no version."

_NO_VERSION_TEMPLATE = "CloudFormation template can't be created from application with no version."


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises; raises on SUCCESS rather than returning a
    falsy sentinel, so planning a deployment of an unpublished application cannot pass silently."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call succeeded; real AWS refuses it")


#: How long a teardown waits for an issued delete to finish: a one-queue stack and its SAR
#: application delete well within it, and all teardowns together fit the cleanup budget.
_CONFIRM_DELETE_S = 300.0


def _ignore_not_found(fn):
    """Run fn, treating an already-gone target as success and retrying a refusal briefly: SAR will
    not delete an application while a stack it planned is still being torn down. Bounded by
    _CONFIRM_DELETE_S; a refusal that outlives the window raises."""
    deadline = time.time() + _CONFIRM_DELETE_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if time.time() >= deadline:
                raise RuntimeError(f"teardown could not complete: {code}: {exc}") from exc
            time.sleep(3)


def _await_version(sar, app_id, semantic_version):
    """Block until SAR serves one specific published version."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    last = None
    while time.time() < deadline:
        try:
            got = sar.get_application(ApplicationId=app_id, SemanticVersion=semantic_version)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
            last = "NotFoundException"
        else:
            if "Version" in got:
                return got["Version"]
            last = sorted(got)
        time.sleep(2)
    raise AssertionError(
        f"GetApplication never served version {semantic_version!r} of {app_id} within "
        f"{_CONSISTENCY_BUDGET_S}s (last saw {last!r})"
    )


def _await_latest(sar, app_id, semantic_version):
    """Block until GetApplication's latest-version pointer reaches semantic_version."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    seen = None
    while time.time() < deadline:
        seen = sar.get_application(ApplicationId=app_id).get("Version", {}).get("SemanticVersion")
        if seen == semantic_version:
            return seen
        time.sleep(2)
    raise AssertionError(
        f"GetApplication's latest-version pointer settled on {seen!r}, expected the published "
        f"{semantic_version!r}"
    )


def _change_set_once_deployable(sar, app_id, stack_name):
    """Ask for a change set with no explicit version, waiting out SAR's own convergence: resolving
    LATEST lags both the pinned read and the latest-version pointer by a few seconds. Only the
    "no version" refusal is waited out; every other error propagates."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    while True:
        try:
            return sar.create_cloud_formation_change_set(
                ApplicationId=app_id, StackName=stack_name, Capabilities=[],
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            unconverged = (err.get("Code") == "BadRequestException"
                           and "no version" in err.get("Message", ""))
            if not unconverged or time.time() >= deadline:
                raise
            time.sleep(3)


def _assert_no_stack(cfn, stack_name, why):
    """Assert CloudFormation holds no stack by that name."""
    code, message = None, None
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, message = err.get("Code"), err.get("Message", "")
    else:
        raise AssertionError(
            f"{why}: CloudFormation holds stack {stack_name!r} with status "
            f"{stacks[0]['StackStatus']!r} — SAR must validate before it creates anything"
        )
    assert (code, message) == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
        f"{why}: reading the stack that must not exist returned {code!r} ({message!r}), expected "
        f"CloudFormation's ValidationError for a missing stack"
    )


def _delete_stack(cfn, stack_id):
    """Delete the stack SAR created (`serverlessrepo-<requested>`) and wait for it to finish,
    bounded by _CONFIRM_DELETE_S; a stack still deleting at the deadline raises."""
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        raise RuntimeError(f"delete_stack({stack_id}) failed: {exc}") from exc
    deadline = time.time() + _CONFIRM_DELETE_S
    while time.time() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if not (
                err.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in err.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_id} reached DELETE_FAILED")
        time.sleep(2)
    raise TimeoutError(f"stack {stack_id} still deleting after {_CONFIRM_DELETE_S:.0f}s")


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """An application with nothing published cannot be deployed: SAR refuses both the change set and
    the generated template, and the refusal creates NO CloudFormation stack — while the identical
    call on the same application succeeds once a version exists.
    """
    sar = ctx.client("serverlessrepo")
    cfn = ctx.client("cloudformation")

    app_name = ctx.unique_name("sim2real-xsvc-sar-")
    app_id = sar.create_application(
        Name=app_name, Author="sim2real xsvc", Description="versionless deploy refused",
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))
    assert "Version" not in sar.get_application(ApplicationId=app_id), (
        "the application under test already has a version; this check needs one with nothing "
        "published"
    )

    requested_stack = ctx.unique_name("sim2real-xsvc-sar-")
    namespaced_stack = f"serverlessrepo-{requested_stack}"

    code, message = _error(lambda: sar.create_cloud_formation_change_set(
        ApplicationId=app_id, StackName=requested_stack, Capabilities=[],
    ))
    assert (code, message) == ("BadRequestException", _NO_VERSION_CHANGE_SET), (
        f"asking for a change set on a versionless application returned {(code, message)!r}, "
        f"expected BadRequestException {_NO_VERSION_CHANGE_SET!r}"
    )
    # An accepted change set creates a REVIEW_IN_PROGRESS stack as a side effect.
    _assert_no_stack(cfn, namespaced_stack, "after the refused change set")

    # The same precondition governs the other deploy-ish path SAR exposes.
    code, message = _error(
        lambda: sar.create_cloud_formation_template(ApplicationId=app_id)
    )
    assert (code, message) == ("BadRequestException", _NO_VERSION_TEMPLATE), (
        f"asking for a generated template on a versionless application returned "
        f"{(code, message)!r}, expected BadRequestException {_NO_VERSION_TEMPLATE!r}"
    )

    # Positive control: publishing a version is the ONLY thing that changes between the refusal
    # above and the acceptance below — same application, same requested stack name, same call.
    sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="1.0.0", TemplateBody=_TEMPLATE,
    )
    _await_version(sar, app_id, "1.0.0")
    _await_latest(sar, app_id, "1.0.0")

    accepted = _change_set_once_deployable(sar, app_id, requested_stack)
    ctx.on_cleanup(lambda: _delete_stack(cfn, accepted["StackId"]))
    assert accepted["SemanticVersion"] == "1.0.0", (
        f"the accepted change set names version {accepted['SemanticVersion']!r}; with one version "
        f"published SAR must plan that one"
    )
    assert accepted["StackId"].split("/")[1] == namespaced_stack, (
        f"SAR created stack {accepted['StackId'].split('/')[1]!r} for requested name "
        f"{requested_stack!r}, expected {namespaced_stack!r}"
    )

    created = cfn.describe_stacks(StackName=accepted["StackId"])["Stacks"][0]
    assert created["StackStatus"] == "REVIEW_IN_PROGRESS", (
        f"the accepted change set left the stack {created['StackStatus']!r}, expected "
        f"REVIEW_IN_PROGRESS — this is what the refused call above must NOT have created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
