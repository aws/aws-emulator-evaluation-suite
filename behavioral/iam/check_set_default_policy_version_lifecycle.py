"""set-default-policy-version-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-default-policy-version-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetDefaultPolicyVersion promoting a non-default version updates
    GetPolicy.DefaultVersionId and flips the IsDefaultVersion flag on both
    the previously-default and newly-default GetPolicyVersion responses."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pol-")

    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{name}-v1"}],
    }
    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}-v2/*"}],
    }

    policy = iam.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps(doc_v1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]
    policy_arn = policy["Arn"]
    assert policy["DefaultVersionId"] == "v1"

    def _cleanup():
        try:
            versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntityException":
                return
            raise
        for v in versions:
            if not v["IsDefaultVersion"]:
                try:
                    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
                except ClientError as err:
                    if err.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        try:
            iam.delete_policy(PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntityException":
                raise

    ctx.on_cleanup(_cleanup)

    v2 = iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=json.dumps(doc_v2), SetAsDefault=False)[
        "PolicyVersion"
    ]
    assert v2["VersionId"] == "v2"
    assert v2["IsDefaultVersion"] is False

    # default is still v1 before promotion
    assert iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"] == "v1"

    iam.set_default_policy_version(PolicyArn=policy_arn, VersionId="v2")

    fetched_policy = _poll_until(
        lambda: iam.get_policy(PolicyArn=policy_arn)["Policy"],
        lambda p: p["DefaultVersionId"] == "v2",
        timeout_s=20.0,
        description="SetDefaultPolicyVersion(v2) reflected in GetPolicy.DefaultVersionId",
    )
    assert fetched_policy["DefaultVersionId"] == "v2"

    v1_after = iam.get_policy_version(PolicyArn=policy_arn, VersionId="v1")["PolicyVersion"]
    v2_after = iam.get_policy_version(PolicyArn=policy_arn, VersionId="v2")["PolicyVersion"]
    assert v1_after["IsDefaultVersion"] is False
    assert v2_after["IsDefaultVersion"] is True


def _poll_until(probe, predicate, *, timeout_s=20.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {result!r}"
            )
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
