"""policy-version-limit-exceeded-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-version-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicyVersion on a policy with 5 versions fails with
    VersionsLimitExceededException and its exact message and leaves the version ids
    unchanged; deleting one lets a new version replace it."""
    iot = ctx.client("iot")

    policy_name = ctx.unique_name("sim2real-iot-polverlimit-")
    iot.create_policy(
        policyName=policy_name,
        policyDocument=_policy_doc(0),
        tags=[{"Key": "sim2real", "Value": "policy-version-limit-exceeded-rejected"}],
    )
    ctx.on_cleanup(lambda: iot.delete_policy(policyName=policy_name))

    version_ids = []
    for i in range(1, 5):
        resp = iot.create_policy_version(policyName=policy_name, policyDocument=_policy_doc(i), setAsDefault=False)
        version_ids.append(resp["policyVersionId"])
        ctx.on_cleanup(lambda vid=resp["policyVersionId"]: _delete_version_ignore(iot, policy_name, vid))

    listed = iot.list_policy_versions(policyName=policy_name)["policyVersions"]
    assert len(listed) == 5, f"expected 5 versions (1 default + 4 created), got {len(listed)}: {listed}"

    code, message = _error_code(lambda: iot.create_policy_version(policyName=policy_name, policyDocument=_policy_doc(99)))
    assert code == "VersionsLimitExceededException", f"expected VersionsLimitExceededException, got {code!r}"
    expected = f"The policy {policy_name} already has the maximum number of versions (5)"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = iot.list_policy_versions(policyName=policy_name)["policyVersions"]
    assert len(listed_after) == 5, f"expected the rejected call to leave 5 versions, got {len(listed_after)}: {listed_after}"
    before_ids = {v["versionId"] for v in listed}
    after_ids = {v["versionId"] for v in listed_after}
    assert after_ids == before_ids, f"expected the version set unchanged after the rejected call, {before_ids} vs {after_ids}"

    # Positive control: freeing a slot lets a new version through -- the rejection above was
    # specifically the 5-version cap, not a blanket refusal to ever version this policy again.
    iot.delete_policy_version(policyName=policy_name, policyVersionId=version_ids[0])
    created = iot.create_policy_version(policyName=policy_name, policyDocument=_policy_doc(100), setAsDefault=False)
    ctx.on_cleanup(lambda vid=created["policyVersionId"]: _delete_version_ignore(iot, policy_name, vid))

    listed_final = iot.list_policy_versions(policyName=policy_name)["policyVersions"]
    assert len(listed_final) == 5, f"expected 5 versions after freeing a slot and recreating, got {len(listed_final)}: {listed_final}"
    final_ids = {v["versionId"] for v in listed_final}
    assert created["policyVersionId"] in final_ids, (
        f"expected the new version {created['policyVersionId']!r} in the list, got {final_ids}"
    )
    assert version_ids[0] not in final_ids, (
        f"expected the freed version {version_ids[0]!r} gone from the list, got {final_ids}"
    )


def _policy_doc(i: int) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Sid": f"sim2real{i}", "Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
        }
    )


def _error_code(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_version_ignore(iot, policy_name: str, version_id: str) -> None:
    try:
        iot.delete_policy_version(policyName=policy_name, policyVersionId=version_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
