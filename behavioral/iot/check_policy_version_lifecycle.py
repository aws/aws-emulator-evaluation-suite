"""policy-version-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "policy-version-lifecycle"
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Multiple policy versions can coexist; SetDefaultPolicyVersion switches GetPolicy's content."""
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-policy-")
    iot.create_policy(
        policyName=name,
        policyDocument=_policy_doc("v1"),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: _delete_policy(iot, _n))

    v2 = iot.create_policy_version(
        policyName=name, policyDocument=_policy_doc("v2"), setAsDefault=False
    )
    versions = iot.list_policy_versions(policyName=name).get("policyVersions", [])
    assert len(versions) == 2, f"expected 2 policy versions after create_policy_version, got {versions}"

    default_before = iot.get_policy(policyName=name)
    doc_before = json.loads(default_before["policyDocument"])
    expected_v1 = json.loads(_policy_doc("v1"))
    assert doc_before == expected_v1, f"expected default GetPolicy doc {expected_v1} before switch, got {doc_before}"

    iot.set_default_policy_version(policyName=name, policyVersionId=v2["policyVersionId"])
    default_after = iot.get_policy(policyName=name)
    doc_after = json.loads(default_after["policyDocument"])
    expected_v2 = json.loads(_policy_doc("v2"))
    assert doc_after == expected_v2, f"expected default GetPolicy doc {expected_v2} after switch, got {doc_after}"
    assert default_after["defaultVersionId"] == v2["policyVersionId"], (
        f"expected defaultVersionId {v2['policyVersionId']!r}, got {default_after['defaultVersionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
