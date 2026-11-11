"""policy-version-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

CHECK = "policy-version-limit"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

ERR_LIMIT_EXCEEDED = "LimitExceeded"

def _version_doc(tag: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:GetUser",
                    "Resource": f"arn:aws:iam::*:user/sim2real-behav-{tag}",
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicyVersion fails LimitExceeded on a 6th version, leaving the same 5 versions;
    after one version is deleted, a new version is created."""
    iam = ctx.client("iam")
    arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]

    def _cleanup_policy(a=arn):
        # A managed policy with non-default versions can't be deleted until they are removed.
        for v in iam.list_policy_versions(PolicyArn=a).get("Versions", []):
            if not v["IsDefaultVersion"]:
                try:
                    iam.delete_policy_version(PolicyArn=a, VersionId=v["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        iam.delete_policy(PolicyArn=a)

    ctx.on_cleanup(_cleanup_policy)
    # v1 already exists from create_policy.
    created_ids = []
    for i in range(2, 6):
        version = iam.create_policy_version(PolicyArn=arn, PolicyDocument=_version_doc(f"v{i}"), SetAsDefault=False)["PolicyVersion"]
        created_ids.append(version["VersionId"])

    versions_before = iam.list_policy_versions(PolicyArn=arn).get("Versions", [])
    assert len(versions_before) == 5, f"expected 5 versions before overflow, got {len(versions_before)}"

    try:
        iam.create_policy_version(PolicyArn=arn, PolicyDocument=_version_doc("v6"), SetAsDefault=False)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_LIMIT_EXCEEDED, f"Expected {ERR_LIMIT_EXCEEDED}, got {code!r}"
    assert message == "A managed policy can have up to 5 versions. Before you create a new version, you must delete an existing version.", (
        f"expected the exact LimitExceeded message AWS returns, got {message!r}"
    )

    versions_after = iam.list_policy_versions(PolicyArn=arn).get("Versions", [])
    assert len(versions_after) == 5, f"expected still 5 versions after rejected call, got {len(versions_after)}"
    assert {v["VersionId"] for v in versions_after} == {v["VersionId"] for v in versions_before}, (
        f"version set changed after rejected create: before={versions_before!r} after={versions_after!r}"
    )

    freed_id = created_ids[0]
    iam.delete_policy_version(PolicyArn=arn, VersionId=freed_id)
    restored = iam.create_policy_version(PolicyArn=arn, PolicyDocument=_version_doc("v7"), SetAsDefault=False)["PolicyVersion"]

    versions_restored = iam.list_policy_versions(PolicyArn=arn).get("Versions", [])
    restored_ids = {v["VersionId"] for v in versions_restored}
    assert len(versions_restored) == 5, f"expected 5 versions after freeing one and creating one, got {len(versions_restored)}"
    assert freed_id not in restored_ids, f"deleted version {freed_id!r} still present: {restored_ids!r}"
    assert restored["VersionId"] in restored_ids, f"newly created version {restored['VersionId']!r} missing: {restored_ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
