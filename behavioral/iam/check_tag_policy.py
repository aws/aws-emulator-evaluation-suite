"""tag-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-policy"
GROUP = 'tags'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _simple_policy_document(actions, resource="*", effect="Allow"):
    """A minimal single-statement identity policy document (JSON string)."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": actions, "Resource": resource}],
        }
    )


def _delete_policy_fully(iam, policy_arn):
    """Delete every non-default version of a managed policy, then the policy itself. DeletePolicy
    fails DeleteConflict while >1 version remains, so cleanup must delete extra versions first."""
    try:
        versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return
    for v in versions:
        if not v.get("IsDefaultVersion"):
            try:
                iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    try:
        iam.delete_policy(PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagPolicy persists tags that GetPolicy / ListPolicyTags then reflect exactly; tagging a
    nonexistent PolicyArn is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    name = ctx.unique_name("policytag-")
    policy = iam.create_policy(
        PolicyName=name, PolicyDocument=_simple_policy_document(["s3:ListBucket"])
    )["Policy"]
    arn = policy["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_fully(iam, arn))

    iam.tag_policy(PolicyArn=arn, Tags=[{"Key": "sim2real-k", "Value": "v1"}])
    ctx.on_cleanup(lambda: iam.untag_policy(PolicyArn=arn, TagKeys=["sim2real-k"]))

    tags = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert {"Key": "sim2real-k", "Value": "v1"} in tags, f"tag missing: {tags}"
    got_tags = iam.get_policy(PolicyArn=arn)["Policy"].get("Tags", [])
    assert {"Key": "sim2real-k", "Value": "v1"} in got_tags, f"GetPolicy omitted the tag: {got_tags}"

    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:iam::{account}:policy/{ctx.unique_name('missing-')}"
    code, message = _error(
        lambda: iam.tag_policy(PolicyArn=fake_arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent PolicyArn, got {code}"
    expected = f"Policy {fake_arn} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
