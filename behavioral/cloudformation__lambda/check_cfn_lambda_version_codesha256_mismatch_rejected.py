"""cfn-lambda-version-codesha256-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-version-codesha256-mismatch-rejected"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = "def handler(event, context):\n    return {'ok': True}\n"
_WRONG_SHA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def _base_template(tok: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": tok, "Runtime": "python3.12", "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
        },
        "Outputs": {"FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}}},
    })


def _with_version(tok: str, code_sha: str) -> str:
    doc = json.loads(_base_template(tok))
    doc["Resources"]["Ver"] = {"Type": "AWS::Lambda::Version", "Properties": {
        "FunctionName": {"Ref": "Fn"}, "CodeSha256": code_sha}}
    doc["Outputs"]["VerNumber"] = {"Value": {"Fn::GetAtt": ["Ver", "Version"]}}
    return json.dumps(doc)


def _poll(probe, predicate, *, timeout_s=_STACK_DEADLINE_S, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Lambda::Version with a mismatched CodeSha256 fails PublishVersion's precondition and
    the update rolls back with no new version, the matching Version unaffected; after the stack
    delete the function answers ResourceNotFoundException and the role NoSuchEntity.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfres-vsha-")
    stack = ctx.unique_name("sim2real-cfres-vshastk-")

    cfn.create_stack(StackName=stack, TemplateBody=_base_template(name),
                      Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack))
    status = _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                   description=f"stack {stack} terminal")
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    actual_sha = lam.get_function(FunctionName=name)["Configuration"]["CodeSha256"]
    assert actual_sha != _WRONG_SHA, "the wrong hash accidentally matched the real one"

    # Positive control: a Version published with the matching hash succeeds through CFN.
    cfn.update_stack(StackName=stack, TemplateBody=_with_version(name, actual_sha),
                     Capabilities=["CAPABILITY_IAM"])
    status = _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                   description=f"stack {stack} terminal after adding the matching Version")
    assert status == "UPDATE_COMPLETE", f"the matching-hash Version update ended {status!r}"
    good_outputs = {o["OutputKey"]: o["OutputValue"] for o in
                    cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    assert good_outputs["VerNumber"] == "1", f"GetAtt Version is {good_outputs['VerNumber']!r}"

    # Establish the exact oracle: Lambda's own precondition on this exact mismatch, called directly.
    code, message = _error(lambda: lam.publish_version(FunctionName=name, CodeSha256=_WRONG_SHA))
    want_code, want_message = "InvalidParameterValueException", (
        f"CodeSHA256 ({_WRONG_SHA}) is different from current CodeSHA256 in $LATEST "
        f"({actual_sha}). Please try again with the CodeSHA256 in $LATEST.")
    assert code == want_code, f"expected {want_code}, got {code}: {message!r}"
    assert message == want_message, f"unexpected message {message!r}, wanted {want_message!r}"

    # Break exactly the CodeSha256 precondition through CFN: a second Version with the wrong hash.
    doc = json.loads(_with_version(name, actual_sha))
    doc["Resources"]["VerBad"] = {"Type": "AWS::Lambda::Version", "Properties": {
        "FunctionName": {"Ref": "Fn"}, "CodeSha256": _WRONG_SHA}}
    cfn.update_stack(StackName=stack, TemplateBody=json.dumps(doc), Capabilities=["CAPABILITY_IAM"])
    status = _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                   description=f"stack {stack} terminal after the mismatched Version")
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"the mismatched-hash update ended {status!r}, expected a rollback"

    events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    failed = [e for e in events if e["LogicalResourceId"] == "VerBad" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed, f"no CREATE_FAILED event for VerBad; statuses were "\
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    assert want_message in reason, (
        f"expected CFN's failure reason to carry the CodeSha256 precondition message "
        f"{want_message!r}; reason was {reason!r}")

    # The effect is absent: no version beyond the one published with the matching hash exists,
    # and that one still resolves exactly as it did before the rejected update.
    versions = {v["Version"] for page in lam.get_paginator("list_versions_by_function").paginate(FunctionName=name)
                for v in page["Versions"]}
    assert versions == {"$LATEST", "1"}, f"expected versions {{'$LATEST', '1'}}, found {versions!r}"
    pub = lam.get_function_configuration(FunctionName=name, Qualifier="1")
    assert pub["CodeSha256"] == actual_sha, (
        f"the matching-hash version's own CodeSha256 changed to {pub['CodeSha256']!r}")

    # Delete the stack in-band: the function and its execution role are gone through their own APIs.
    role_name = cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId="ExecRole")["StackResourceDetail"]["PhysicalResourceId"]
    _delete_stack(ctx, cfn, stack)
    code, message = _error(lambda: lam.get_function(FunctionName=name))
    want = f"Function not found: {good_outputs['FnArn']}"
    assert (code, message) == ("ResourceNotFoundException", want), (
        f"GetFunction after the stack delete answered {(code, message)!r}, expected "
        f"('ResourceNotFoundException', {want!r})")
    code, message = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    want = f"The role with name {role_name} cannot be found."
    assert (code, message) == ("NoSuchEntity", want), (
        f"GetRole of the deleted stack's role answered {(code, message)!r}, expected ('NoSuchEntity', {want!r})")


def _delete_stack(ctx, cfn, stack: str) -> None:
    status = _stack_status(cfn, stack)
    if status == "GONE":
        return
    if status.endswith("_IN_PROGRESS"):
        _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
              description=f"stack {stack} terminal before delete")
    cfn.delete_stack(StackName=stack)
    final = _poll(lambda: _stack_status(cfn, stack), lambda s: s in ("GONE", "DELETE_FAILED"),
                  description=f"stack {stack} deleted")
    if final != "GONE":
        raise AssertionError(f"stack {stack} did not reach DELETE_COMPLETE, ended {final!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
