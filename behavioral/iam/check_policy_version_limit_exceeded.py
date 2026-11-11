"""policy-version-limit-exceeded."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-version-limit-exceeded"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 6th CreatePolicyVersion fails LimitExceeded (HTTP 409, exact message) leaving 5 versions;
    after deleting one, the same call succeeds. The deleted policy then reads NoSuchEntity (404)."""
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-verlimit-")
    base_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sim2real-base/*"}],
    }
    policy_arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(base_doc))["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_policy(PolicyArn=policy_arn)))

    created_version_ids = []
    for i in range(4):
        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::sim2real-v{i}/*",
            }],
        }
        version = iam.create_policy_version(
            PolicyArn=policy_arn, PolicyDocument=json.dumps(doc), SetAsDefault=False
        )["PolicyVersion"]
        created_version_ids.append(version["VersionId"])

    versions_before = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_before) == 5, f"expected 5 versions before overflow, got {len(versions_before)}"
    for vid in created_version_ids:
        ctx.on_cleanup(lambda vid=vid: _ignore_no_such_entity(
            lambda: iam.delete_policy_version(PolicyArn=policy_arn, VersionId=vid)
        ))

    overflow_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sim2real-overflow/*"}],
    }
    code, status, message = _expect_rejected(
        ctx,
        iam,
        policy_arn,
        lambda: iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=json.dumps(overflow_doc)),
    )
    assert code == "LimitExceeded", f"expected LimitExceeded, got {code!r}"
    assert status == 409, f"expected HTTP 409 for LimitExceeded, got {status!r}"
    expected_message = "A managed policy can have up to 5 versions. Before you create a new version, you must delete an existing version."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    versions_after = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_after) == 5, f"expected still 5 versions after rejected call, got {len(versions_after)}"
    assert {v["VersionId"] for v in versions_after} == {v["VersionId"] for v in versions_before}

    freed_vid = created_version_ids[0]
    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=freed_vid)

    restored = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(overflow_doc), SetAsDefault=False
    )["PolicyVersion"]
    restored_vid = restored["VersionId"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(
        lambda: iam.delete_policy_version(PolicyArn=policy_arn, VersionId=restored_vid)
    ))

    versions_restored = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    restored_ids = {v["VersionId"] for v in versions_restored}
    assert len(versions_restored) == 5, f"expected 5 versions after restore, got {len(versions_restored)}"
    assert freed_vid not in restored_ids, f"freed version {freed_vid!r} still present after delete"
    assert restored_vid in restored_ids, f"restored version {restored_vid!r} missing after the retried call succeeded"

    # Non-default versions must be deleted before the policy can be.
    for v in versions_restored:
        if not v["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
    iam.delete_policy(PolicyArn=policy_arn)
    try:
        gone = iam.get_policy(PolicyArn=policy_arn)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert err.get("Code") == "NoSuchEntity" and got_status == 404, (
            f"expected NoSuchEntity/404 for the deleted policy, got {err.get('Code')!r}/{got_status!r}"
        )
        expected_message = f"Policy {policy_arn} was not found."
        assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'
    else:
        raise AssertionError(f"GetPolicy still serves the deleted policy: {gone.get('Policy')!r}")


def _expect_rejected(ctx, iam, policy_arn, fn):
    """Call fn(); return its ClientError (code, HTTP status, message).
    An unexpected success registers the created version for cleanup, then raises."""
    from botocore.exceptions import ClientError
    try:
        version = fn()["PolicyVersion"]
    except ClientError as e:
        return (
            e.response["Error"]["Code"],
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            e.response["Error"].get("Message"),
        )
    vid = version["VersionId"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(
        lambda: iam.delete_policy_version(PolicyArn=policy_arn, VersionId=vid)
    ))
    raise AssertionError(f"expected LimitExceeded, but CreatePolicyVersion succeeded and returned version {vid!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
