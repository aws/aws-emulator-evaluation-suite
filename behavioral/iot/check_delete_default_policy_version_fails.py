"""delete-default-policy-version-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-default-policy-version-fails"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _policy_doc(effect: str = "Allow", version: int = 1) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": effect,
                    "Action": "iot:Connect",
                    "Resource": f"arn:aws:iot:*:*:client/probe-{version}",
                }
            ],
        }
    )

def _delete_policy(iot, name):
    """Best-effort teardown: delete non-default versions, detach targets, then delete a policy."""
    try:
        for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_targets_for_policy(policyName=name).get("targets", []):
            iot.detach_policy(policyName=name, target=t)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicyVersion on the current default version must fail with DeleteConflictException,
    the default version stays intact and still default, and deleting a non-default version (the
    positive control, in the same file) still succeeds."""
    iot = ctx.client("iot")
    policy_name = ctx.unique_name("sim2real-behav-policy-defver-")
    resp = iot.create_policy(
        policyName=policy_name,
        policyDocument=_policy_doc(),
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=policy_name: _delete_policy(iot, _n))
    default_version = resp["policyVersionId"]

    non_default = iot.create_policy_version(
        policyName=policy_name, policyDocument=_policy_doc(version=2), setAsDefault=False
    )
    non_default_version = non_default["policyVersionId"]

    # Break exactly one thing: try to delete the current default version.
    code, message = _err(
        lambda: iot.delete_policy_version(policyName=policy_name, policyVersionId=default_version)
    )
    assert code == "DeleteConflictException", f"expected DeleteConflictException, got {code}"
    expected_message = f"Cannot delete a default policy version (name={policy_name}, versionId={default_version})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the default version is still there, and still the default.
    versions_after = iot.list_policy_versions(policyName=policy_name).get("policyVersions", [])
    still_default = next((v for v in versions_after if v["versionId"] == default_version), None)
    assert still_default is not None, versions_after
    assert still_default["isDefaultVersion"] is True, still_default

    # Positive control: deleting a non-default version on the same policy still succeeds --
    # the rejection above is specific to the current default, not a blanket refusal.
    iot.delete_policy_version(policyName=policy_name, policyVersionId=non_default_version)
    versions_final = iot.list_policy_versions(policyName=policy_name).get("policyVersions", [])
    assert not any(v["versionId"] == non_default_version for v in versions_final), versions_final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
