"""set-default-policy-version-invalid-version-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-default-policy-version-invalid-version-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetDefaultPolicyVersion rejects a nonexistent VersionId with NoSuchEntity and keeps the
    current default, while an existing VersionId is accepted and becomes the default."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pol-badver-")
    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{name}"}],
    }
    policy = iam.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps(doc_v1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]
    policy_arn = policy["Arn"]

    def _cleanup():
        try:
            versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            raise
        for v in versions:
            if not v["IsDefaultVersion"]:
                iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
        iam.delete_policy(PolicyArn=policy_arn)

    ctx.on_cleanup(_cleanup)

    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"}],
    }
    v2 = iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=json.dumps(doc_v2), SetAsDefault=False)[
        "PolicyVersion"
    ]["VersionId"]

    # positive control: a VersionId that exists is accepted and becomes the default.
    iam.set_default_policy_version(PolicyArn=policy_arn, VersionId=v2)
    promoted = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    assert promoted == v2, f"expected default version to become {v2!r} after a valid promotion, got {promoted!r}"

    code, msg = _error(lambda: iam.set_default_policy_version(PolicyArn=policy_arn, VersionId="v99"))
    # The wire Error.Code is "NoSuchEntity", without the "Exception" suffix of the class name.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    want = f"Policy {policy_arn} version v99 does not exist or is not attachable."
    assert msg == want, f"NoSuchEntity message: wanted {want!r}, got {msg!r}"

    # Still v2 from the positive control, not reverted to v1.
    after = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    assert after == v2, f"expected default version to remain {v2!r} after the rejected call, got {after!r}"


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
