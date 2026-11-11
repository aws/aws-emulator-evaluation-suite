"""policy-versions-create-and-list."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

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

CHECK = "policy-versions-create-and-list"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicyVersion adds a new version; ListPolicyVersions shows both, and only the new one is default."""
    iam = ctx.client("iam")
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": "policy-versions-create-and-list"}],
    )["Policy"]["Arn"]

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
    new_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:ListUsers",
                    "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
                }
            ],
        }
    )
    iam.create_policy_version(PolicyArn=arn, PolicyDocument=new_doc, SetAsDefault=True)
    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    assert len(versions) == 2, f"expected exactly 2 versions (v1 + new), got {len(versions)}: {versions}"
    version_ids = [v["VersionId"] for v in versions]
    assert "v1" in version_ids, f"expected v1 in {version_ids}"
    assert "v2" in version_ids, f"expected v2 in {version_ids}"
    default_ids = [v["VersionId"] for v in versions if v["IsDefaultVersion"]]
    assert default_ids == ["v2"], f"expected only v2 to be the default version, got {default_ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
