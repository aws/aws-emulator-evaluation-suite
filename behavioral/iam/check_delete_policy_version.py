"""delete-policy-version."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

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

CHECK = "delete-policy-version"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicyVersion removes a non-default version, and the removed
    version becomes both invisible and unusable while the default is untouched."""
    iam = ctx.client("iam")
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": "delete-policy-version"}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    new_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:GetUser",
                    "Resource": "arn:aws:iam::*:user/sim2real-behav-del",
                }
            ],
        }
    )
    iam.create_policy_version(PolicyArn=arn, PolicyDocument=new_doc, SetAsDefault=False)

    # positive control: v2 is really there via an independent read, before we touch it
    before_ids = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]]
    assert "v2" in before_ids, f"expected v2 present after create_policy_version, got {before_ids}"

    iam.delete_policy_version(PolicyArn=arn, VersionId="v2")

    after_ids = [v["VersionId"] for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]]
    assert "v2" not in after_ids, f"expected v2 removed after delete_policy_version, got {after_ids}"
    assert "v1" in after_ids, f"expected default version v1 untouched, got {after_ids}"

    # the deleted version is not just absent from the list, it is unusable
    get_code, get_message = _error(lambda: iam.get_policy_version(PolicyArn=arn, VersionId="v2"))
    assert get_code == "NoSuchEntity", f"expected NoSuchEntity reading deleted version v2, got {get_code}"
    expected_get = f"Policy {arn} version v2 does not exist or is not attachable."
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"
    delete_code, delete_message = _error(lambda: iam.delete_policy_version(PolicyArn=arn, VersionId="v2"))
    assert delete_code == "NoSuchEntity", f"expected NoSuchEntity re-deleting version v2, got {delete_code}"
    expected_delete = f"Policy {arn} version v2 does not exist or is not attachable."
    assert delete_message == expected_delete, f"expected message {expected_delete!r}, got {delete_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
