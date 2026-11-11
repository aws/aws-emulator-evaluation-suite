"""policy-version-limit-exceeded."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-version-limit-exceeded"
GROUP = 'policy-lifecycle'
SERVICES = ['iot']

def _policy_doc(version_tag: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iot:Publish",
                    # IoT validates policy resources: they must be wildcards or
                    # well-formed IoT ARNs, so build a real topic ARN per version.
                    "Resource": f"arn:aws:iot:*:*:topic/sim2real-behav/{version_tag}",
                }
            ],
        }
    )

def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
    """The sixth CreatePolicyVersion fails with VersionsLimitExceededException and its
    exact message and leaves the same 5 version ids; after deleting a non-default version
    a new one is created."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-policy-limit-")
    iot.create_policy(
        policyName=name,
        policyDocument=_policy_doc("v1"),
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: _delete_policy(iot, _n))

    for i in range(2, 6):
        iot.create_policy_version(policyName=name, policyDocument=_policy_doc(f"v{i}"))

    versions = iot.list_policy_versions(policyName=name).get("policyVersions", [])
    assert len(versions) == 5, versions
    version_ids_before = {v["versionId"] for v in versions}

    code, message = _err(
        lambda: iot.create_policy_version(policyName=name, policyDocument=_policy_doc("v6"))
    )
    assert code == "VersionsLimitExceededException", f"expected VersionsLimitExceededException, got {code}"
    expected = f"The policy {name} already has the maximum number of versions (5)"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the rejected call left no trace: the identical set of 5 version ids, not merely the
    # same count (a target that silently evicted the oldest version to make room would pass
    # a bare len() check but fail this one)
    versions_after = iot.list_policy_versions(policyName=name).get("policyVersions", [])
    assert len(versions_after) == 5, versions_after
    assert {v["versionId"] for v in versions_after} == version_ids_before, versions_after

    # positive control / restore leg: freeing a slot lets a new version through
    non_default = next(v for v in versions_after if not v.get("isDefaultVersion"))
    iot.delete_policy_version(policyName=name, policyVersionId=non_default["versionId"])
    created = iot.create_policy_version(policyName=name, policyDocument=_policy_doc("v7"))

    versions_final = iot.list_policy_versions(policyName=name).get("policyVersions", [])
    assert len(versions_final) == 5, versions_final
    assert created["policyVersionId"] in {v["versionId"] for v in versions_final}, versions_final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
