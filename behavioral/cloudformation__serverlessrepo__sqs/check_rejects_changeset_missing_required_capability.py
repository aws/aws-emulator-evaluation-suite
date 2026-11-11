"""rejects-changeset-missing-required-capability."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rejects-changeset-missing-required-capability"
GROUP = 'deploy-sar-changeset'
SERVICES = ['cloudformation', 'serverlessrepo', 'sqs']

# SAR's read path is eventually consistent: CreateApplicationVersion returns synchronously, but
# GetApplication can take several seconds to serve the new version.
_CONSISTENCY_BUDGET_S = 120.0


def _anonymous_iam_template():
    """A SAM template whose only resource is an IAM role with a GENERATED name."""
    return """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  Q:
    Type: AWS::SQS::Queue
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
"""


def _named_iam_template(role_name):
    """The same template with the role's name PINNED, which is what raises the bar to NAMED_IAM."""
    return _anonymous_iam_template().replace(
        "    Properties:\n      AssumeRolePolicyDocument:",
        f"    Properties:\n      RoleName: {role_name}\n      AssumeRolePolicyDocument:",
    )


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises; raises AssertionError if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("CreateCloudFormationChangeSet succeeded; real AWS refuses it")


#: How long a teardown waits for an issued delete to finish: a one-queue stack and its SAR
#: application delete well within it, and all teardowns together fit the cleanup budget.
_CONFIRM_DELETE_S = 300.0


def _ignore_not_found(fn):
    """Run fn, treating an already-gone target as success and retrying a refusal briefly.

    SAR refuses to delete an application while a stack it planned is still being torn down.
    """
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
    """Block until SAR serves one specific published version, and return its Version block."""
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


def _assert_no_stack(cfn, stack_name, why):
    """Assert CloudFormation holds no stack by that name."""
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, message = err.get("Code"), err.get("Message", "")
    else:
        raise AssertionError(
            f"{why}: CloudFormation holds stack {stack_name!r} with status "
            f"{stacks[0]['StackStatus']!r} — a refused change set must create nothing"
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
    """SAR refuses a change set lacking the version's required capabilities and creates no stack.

    It derives the requirement per version and treats capabilities as a hierarchy: NAMED_IAM
    satisfies an IAM requirement, the reverse is refused.
    """
    sar = ctx.client("serverlessrepo")
    cfn = ctx.client("cloudformation")

    role_name = ctx.unique_name("sim2real-xsvc-sar-")
    app_name = ctx.unique_name("sim2real-xsvc-sar-")
    app_id = sar.create_application(
        Name=app_name, Author="sim2real xsvc", Description="required capabilities",
        SemanticVersion="1.0.0", TemplateBody=_anonymous_iam_template(),
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    named = sar.create_application_version(
        ApplicationId=app_id, SemanticVersion="1.1.0",
        TemplateBody=_named_iam_template(role_name),
    )
    assert named["RequiredCapabilities"] == ["CAPABILITY_NAMED_IAM"], (
        f"a template pinning RoleName required capabilities {named['RequiredCapabilities']!r}, "
        f"expected ['CAPABILITY_NAMED_IAM'] — naming the role is what raises the bar"
    )
    assert _await_version(sar, app_id, "1.0.0")["RequiredCapabilities"] == ["CAPABILITY_IAM"], (
        "version 1.0.0, whose role is unnamed, must require only CAPABILITY_IAM; the requirement "
        "is derived per version, not per application"
    )
    _await_version(sar, app_id, "1.1.0")

    # Refusal 1: the requirement of the version being deployed was not acknowledged at all.
    unacknowledged = ctx.unique_name("sim2real-xsvc-sar-")
    code, message = _error(lambda: sar.create_cloud_formation_change_set(
        ApplicationId=app_id, SemanticVersion="1.0.0", StackName=unacknowledged, Capabilities=[],
    ))
    assert code == "BadRequestException", (
        f"planning a deployment with no capabilities returned {code!r}, expected "
        f"BadRequestException"
    )
    assert "Required capabilities [CAPABILITY_IAM] were not provided." == message, (
        f"the refusal message was {message!r}; real AWS names the missing capability exactly: "
        f"'Required capabilities [CAPABILITY_IAM] were not provided.'"
    )
    _assert_no_stack(cfn, f"serverlessrepo-{unacknowledged}",
                     "after a change set refused for missing CAPABILITY_IAM")

    # Refusal 2: the WEAKER capability does not satisfy the stronger requirement.
    too_weak = ctx.unique_name("sim2real-xsvc-sar-")
    code, message = _error(lambda: sar.create_cloud_formation_change_set(
        ApplicationId=app_id, SemanticVersion="1.1.0", StackName=too_weak,
        Capabilities=["CAPABILITY_IAM"],
    ))
    assert code == "BadRequestException", (
        f"planning a named-IAM deployment with only CAPABILITY_IAM returned {code!r}, expected "
        f"BadRequestException"
    )
    assert "Required capabilities [CAPABILITY_NAMED_IAM] were not provided." == message, (
        f"the refusal message was {message!r}; real AWS names CAPABILITY_NAMED_IAM as the missing "
        f"capability"
    )
    _assert_no_stack(cfn, f"serverlessrepo-{too_weak}",
                     "after a change set refused for missing CAPABILITY_NAMED_IAM")

    # Positive control 1: the requirement IS satisfiable, by acknowledging it.
    acknowledged = ctx.unique_name("sim2real-xsvc-sar-")
    planned = sar.create_cloud_formation_change_set(
        ApplicationId=app_id, SemanticVersion="1.1.0", StackName=acknowledged,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, planned["StackId"]))
    assert cfn.describe_stacks(
        StackName=planned["StackId"])["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS", (
        "acknowledging CAPABILITY_NAMED_IAM must produce the REVIEW_IN_PROGRESS stack that the two "
        "refusals above did not"
    )

    # Positive control 2: the STRONGER capability satisfies the weaker requirement. Same version as
    # refusal 1, same call, one field different — so the refusal there was about the capability and
    # this acceptance is not set equality.
    stronger = ctx.unique_name("sim2real-xsvc-sar-")
    superset = sar.create_cloud_formation_change_set(
        ApplicationId=app_id, SemanticVersion="1.0.0", StackName=stronger,
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, superset["StackId"]))
    assert superset["SemanticVersion"] == "1.0.0", (
        f"the change set names version {superset['SemanticVersion']!r}, expected 1.0.0"
    )
    assert cfn.describe_stacks(
        StackName=superset["StackId"])["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS", (
        "offering CAPABILITY_NAMED_IAM where only CAPABILITY_IAM is required must be accepted — "
        "SAR compares capabilities as a hierarchy, not as a set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
