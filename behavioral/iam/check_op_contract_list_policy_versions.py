"""op-contract-list-policy-versions."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-policy-versions"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """ListPolicyVersions reports both the default v1 and a newly added non-default v2;
    bogus PolicyArn -> NoSuchEntityException."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(doc_v1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    v2 = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=json.dumps(doc_v2), SetAsDefault=False
    )["PolicyVersion"]
    ctx.on_cleanup(
        lambda: iam.delete_policy_version(
            PolicyArn=policy_arn, VersionId=v2["VersionId"]
        )
    )

    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions) == 2, f"expected 2 versions, got {len(versions)}: {versions}"
    default_versions = [v["VersionId"] for v in versions if v["IsDefaultVersion"]]
    non_default_versions = [
        v["VersionId"] for v in versions if not v["IsDefaultVersion"]
    ]
    assert default_versions == ["v1"], (
        f"expected default version ['v1'], got {default_versions}"
    )
    assert non_default_versions == [v2["VersionId"]], (
        f"expected non-default version [{v2['VersionId']!r}], got {non_default_versions}"
    )

    bogus_arn = f"arn:aws:iam::{account_id}:policy/{ctx.unique_name('sim2real-nope-')}"
    code, message = _error(lambda: iam.list_policy_versions(PolicyArn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Policy {bogus_arn} does not exist or is not attachable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
