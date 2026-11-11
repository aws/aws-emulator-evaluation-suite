"""policy-version-delete-default-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-version-delete-default-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicyVersion on the default version fails DeleteConflict with AWS's exact message and
    leaves it default; once another version is default, the same delete succeeds."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pol-deldef-")
    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{name}"}],
    }
    created = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc_v1))["Policy"]
    policy_arn = created["Arn"]
    default_version_id = created["DefaultVersionId"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"}],
    }

    control_id = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(doc_v2), SetAsDefault=False
    )["PolicyVersion"]["VersionId"]
    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=control_id)
    versions = {v["VersionId"]: v for v in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]}
    assert control_id not in versions, f"expected {control_id} gone after positive-control delete, got {versions}"

    # IAM's wire error code omits the "Exception" suffix of the modeled exception name (the class
    # is DeleteConflictException, but the response Error.Code is "DeleteConflict").
    code, message = _error_code(
        lambda: iam.delete_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
    )
    assert code == "DeleteConflict", f"expected DeleteConflict, got {code}"
    expected = "Cannot delete the default version of a policy."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    versions = {v["VersionId"]: v for v in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]}
    assert default_version_id in versions, f"rejected delete must not remove {default_version_id}, got {versions}"
    assert versions[default_version_id]["IsDefaultVersion"] is True, (
        f"expected {default_version_id} to remain default, got {versions[default_version_id]}"
    )

    other_id = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(doc_v2), SetAsDefault=True
    )["PolicyVersion"]["VersionId"]
    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
    versions = {v["VersionId"]: v for v in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]}
    assert default_version_id not in versions, (
        f"expected {default_version_id} deletable once no longer default, got {versions}"
    )
    assert versions[other_id]["IsDefaultVersion"] is True, f"expected {other_id} now default, got {versions}"


def _error_code(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
