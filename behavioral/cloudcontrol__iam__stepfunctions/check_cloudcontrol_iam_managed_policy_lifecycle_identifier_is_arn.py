"""cloudcontrol-iam-managed-policy-lifecycle-identifier-is-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-iam-managed-policy-lifecycle-identifier-is-arn"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "iam", "stepfunctions"]

_POLICY_V1 = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sim2real-xsvc-none/*"}]}
_POLICY_V2 = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::sim2real-xsvc-none/*"}]}
_TYPE = "AWS::IAM::ManagedPolicy"


def _delete_policy(iam, arn: str) -> None:
    """Delete a customer managed policy natively: non-default versions first, then the policy."""
    for version in iam.list_policy_versions(PolicyArn=arn)["Versions"]:
        if not version["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=arn, VersionId=version["VersionId"])
    iam.delete_policy(PolicyArn=arn)


def _list_identifiers(cloudcontrol) -> set[str]:
    identifiers: set[str] = set()
    kwargs: dict = {"TypeName": _TYPE}
    while True:
        page = cloudcontrol.list_resources(**kwargs)
        identifiers |= {d["Identifier"] for d in page.get("ResourceDescriptions", [])}
        if not page.get("NextToken"):
            return identifiers
        kwargs["NextToken"] = page["NextToken"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Cloud Control AWS::IAM::ManagedPolicy is the IAM policy itself: its identifier is the
    policy ARN, its document is IAM's default version, a PolicyDocument patch mints v2 (v1 kept),
    and a Cloud Control delete makes IAM answer NoSuchEntity and drops it from ListResources."""
    ctx.verify_account_safety()
    cloudcontrol = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-ccmp-")
    expected_arn = f"arn:aws:iam::{ctx.account}:policy/{name}"
    ctx.on_cleanup(_teardown(lambda: _delete_policy(iam, expected_arn), "NoSuchEntity"))

    created = _cc_wait(cloudcontrol, cloudcontrol.create_resource(
        TypeName=_TYPE, DesiredState=json.dumps({
            "ManagedPolicyName": name, "PolicyDocument": _POLICY_V1,
            "Description": "sim2real cloudcontrol managed policy"})),
        description=f"cloudcontrol create {_TYPE}")
    assert created["OperationStatus"] == "SUCCESS", (
        f"create ended {created['OperationStatus']!r}: {created.get('ErrorCode')!r} "
        f"{created.get('StatusMessage')!r}"
    )
    identifier = created["Identifier"]
    assert identifier == expected_arn, (
        f"the primary identifier is not the policy ARN for the created name: shape "
        f"{identifier.split(':')[:5]!r}, ends with the name: {identifier.endswith(name)!r}"
    )

    native = iam.get_policy(PolicyArn=identifier)["Policy"]
    assert native["Arn"] == identifier and native["PolicyName"] == name, (
        f"IAM resolves the identifier to policy {native['PolicyName']!r}"
    )
    assert native["DefaultVersionId"] == "v1", f"a new policy's default is {native['DefaultVersionId']!r}"
    v1 = iam.get_policy_version(PolicyArn=identifier, VersionId="v1")["PolicyVersion"]["Document"]
    assert v1 == _POLICY_V1, f"IAM serves v1 as {v1!r}, the desired state sent {_POLICY_V1!r}"

    props = json.loads(cloudcontrol.get_resource(
        TypeName=_TYPE, Identifier=identifier)["ResourceDescription"]["Properties"])
    assert props.get("PolicyArn") == identifier, f"GetResource PolicyArn differs from the identifier"
    assert props.get("PolicyDocument") == _POLICY_V1, (
        f"GetResource PolicyDocument {props.get('PolicyDocument')!r} != {_POLICY_V1!r}"
    )
    assert props.get("DefaultVersionId") == "v1", f"GetResource DefaultVersionId {props.get('DefaultVersionId')!r}"

    assert identifier in _list_identifiers(cloudcontrol), "ListResources does not list the created policy"

    updated = _cc_wait(cloudcontrol, cloudcontrol.update_resource(
        TypeName=_TYPE, Identifier=identifier,
        PatchDocument=json.dumps([{"op": "replace", "path": "/PolicyDocument", "value": _POLICY_V2}])),
        description="cloudcontrol update PolicyDocument")
    assert updated["OperationStatus"] == "SUCCESS", (
        f"update ended {updated['OperationStatus']!r}: {updated.get('StatusMessage')!r}"
    )
    native = iam.get_policy(PolicyArn=identifier)["Policy"]
    assert native["DefaultVersionId"] == "v2", (
        f"after a PolicyDocument patch IAM's default version is {native['DefaultVersionId']!r}, expected 'v2'"
    )
    versions = {v["VersionId"]: v["IsDefaultVersion"]
                for v in iam.list_policy_versions(PolicyArn=identifier)["Versions"]}
    assert versions == {"v1": False, "v2": True}, f"IAM policy versions are {versions!r}"
    v2 = iam.get_policy_version(PolicyArn=identifier, VersionId="v2")["PolicyVersion"]["Document"]
    assert v2 == _POLICY_V2, f"IAM serves v2 as {v2!r}"
    v1 = iam.get_policy_version(PolicyArn=identifier, VersionId="v1")["PolicyVersion"]["Document"]
    assert v1 == _POLICY_V1, f"the patch rewrote v1 to {v1!r}"
    props = json.loads(cloudcontrol.get_resource(
        TypeName=_TYPE, Identifier=identifier)["ResourceDescription"]["Properties"])
    assert props.get("PolicyDocument") == _POLICY_V2 and props.get("DefaultVersionId") == "v2", (
        f"GetResource after the patch reports {props.get('DefaultVersionId')!r} {props.get('PolicyDocument')!r}"
    )

    deleted = _cc_wait(cloudcontrol, cloudcontrol.delete_resource(TypeName=_TYPE, Identifier=identifier),
                       description="cloudcontrol delete")
    assert deleted["OperationStatus"] == "SUCCESS", (
        f"delete ended {deleted['OperationStatus']!r}: {deleted.get('StatusMessage')!r}"
    )
    code, message = _error(lambda: iam.get_policy(PolicyArn=identifier))
    assert code == "NoSuchEntity", f"IAM get_policy after the Cloud Control delete gave {code!r}"
    assert message == f"Policy {expected_arn} was not found.", f"IAM not-found message was {message!r}"
    # message varies: Cloud Control's not-found text embeds per-call IAM and Cloud Control request ids.
    code, _ = _error(lambda: cloudcontrol.get_resource(TypeName=_TYPE, Identifier=identifier))
    assert code == "ResourceNotFoundException", f"GetResource after delete gave {code!r}"
    assert identifier not in _list_identifiers(cloudcontrol), "ListResources still lists the deleted policy"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cc_wait(cloudcontrol, response: dict, *, description: str, timeout_s=300.0) -> dict:
    """Poll a Cloud Control ProgressEvent to a terminal OperationStatus and return it."""
    event = response["ProgressEvent"]
    token = event["RequestToken"]
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    if event.get("OperationStatus") in terminal:
        return event
    return _poll_until(
        lambda: cloudcontrol.get_resource_request_status(RequestToken=token)["ProgressEvent"],
        lambda e: e.get("OperationStatus") in terminal,
        timeout_s=timeout_s, interval_s=3.0, description=description,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
