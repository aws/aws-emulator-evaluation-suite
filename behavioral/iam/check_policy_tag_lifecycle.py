"""policy-tag-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-tag-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags attach to a customer-managed policy via TagPolicy, are visible via
    ListPolicyTags, and a targeted key disappears after UntagPolicy while an
    untouched key survives."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-pol-tags-")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{name}"}],
    }
    policy_arn = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    _retry_until_success(
        lambda: iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "Environment", "Value": "sim2real-test"},
                {"Key": "Owner", "Value": "behavioral-suite"},
            ],
        )
    )

    tags = _tagmap(iam.list_policy_tags(PolicyArn=policy_arn)["Tags"])
    assert tags.get("Environment") == "sim2real-test", (
        f"expected tag Environment=sim2real-test after TagPolicy, got {tags}"
    )
    assert tags.get("Owner") == "behavioral-suite", (
        f"expected tag Owner=behavioral-suite after TagPolicy, got {tags}"
    )

    iam.untag_policy(PolicyArn=policy_arn, TagKeys=["Environment"])

    tags_after = _tagmap(iam.list_policy_tags(PolicyArn=policy_arn)["Tags"])
    assert "Environment" not in tags_after, (
        f"expected Environment removed after UntagPolicy, still present in {tags_after}"
    )
    assert tags_after.get("Owner") == "behavioral-suite", (
        f"expected untouched tag Owner=behavioral-suite to survive UntagPolicy, got {tags_after}"
    )


def _tagmap(tags):
    return {t["Key"]: t["Value"] for t in tags}


def _retry_until_success(fn, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchEntityException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
