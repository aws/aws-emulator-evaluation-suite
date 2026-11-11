"""op-contract-create-policy-version."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-create-policy-version"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _document(marker: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Sid": marker, "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicyVersion adds a non-default version and SetAsDefault moves DefaultVersionId; a 6th
    version is rejected with LimitExceeded without changing the set, and freeing a slot lets it
    succeed again.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
    """
    iam = ctx.client("iam")

    policy_name = ctx.unique_name("sim2real-policy-")
    created = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=_document("v1"),
        Tags=[{"Key": "sim2real", "Value": "op-contract-create-policy-version"}],
    )["Policy"]
    policy_arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_and_versions(iam, policy_arn))
    assert created["DefaultVersionId"] == "v1", (
        f"expected a freshly created policy's DefaultVersionId to be 'v1', got {created['DefaultVersionId']!r}"
    )

    v2 = iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=_document("v2"))["PolicyVersion"]
    assert v2["IsDefaultVersion"] is False, (
        f"expected v2 (no SetAsDefault) to not be default, got IsDefaultVersion={v2['IsDefaultVersion']!r}"
    )

    v3 = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=_document("v3"), SetAsDefault=True
    )["PolicyVersion"]
    assert v3["IsDefaultVersion"] is True, (
        f"expected v3 (SetAsDefault=True) to be default, got IsDefaultVersion={v3['IsDefaultVersion']!r}"
    )
    default_after_v3 = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    assert default_after_v3 == v3["VersionId"], (
        f"expected GetPolicy DefaultVersionId to follow SetAsDefault to {v3['VersionId']!r}, got {default_after_v3!r}"
    )

    # Fill up to the 5-version cap (v1, v2, v3 already exist -> add v4, v5).
    v4 = iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=_document("v4"))["PolicyVersion"]
    iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=_document("v5"))
    versions_at_cap = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_at_cap) == 5, f"expected 5 versions, got {len(versions_at_cap)}"
    version_ids_at_cap = {v["VersionId"] for v in versions_at_cap}

    _assert_rejects_over_cap(
        lambda: iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=_document("overflow"))
    )

    # Independent read: the rejected call must not have changed the version set at all.
    versions_after_rejection = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_after_rejection) == 5, (
        f"rejected create_policy_version must not add a version, expected 5, got {len(versions_after_rejection)}"
    )
    assert {v["VersionId"] for v in versions_after_rejection} == version_ids_at_cap, (
        "rejected create_policy_version changed the version set: "
        f"before={sorted(version_ids_at_cap)}, after={sorted(v['VersionId'] for v in versions_after_rejection)}"
    )

    # Restore beat: freeing a slot below the cap must make the identical call succeed again.
    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v4["VersionId"])
    restored = iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=_document("restored"))["PolicyVersion"]
    versions_final = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    final_ids = {v["VersionId"] for v in versions_final}
    assert restored["VersionId"] in final_ids, (
        f"expected the post-restore version {restored['VersionId']!r} among {sorted(final_ids)}"
    )
    assert len(versions_final) == 5, f"expected 5 versions after restore-and-recreate, got {len(versions_final)}"


def _delete_policy_and_versions(iam, policy_arn: str) -> None:
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    for v in versions:
        if not v["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
    iam.delete_policy(PolicyArn=policy_arn)


def _assert_rejects_over_cap(fn):
    """Call fn(); assert it raises LimitExceeded. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "LimitExceeded", f"expected LimitExceeded (max 5 versions/policy), got {code!r}"
        return
    raise AssertionError(f"real AWS rejects a 6th policy version, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
