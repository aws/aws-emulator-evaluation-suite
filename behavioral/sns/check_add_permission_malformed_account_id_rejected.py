"""add-permission-malformed-account-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-malformed-account-id-rejected"
GROUP = 'topic-policy'
SERVICES = ['sns']


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _sids(sns, arn):
    return {s.get("Sid") for s in json.loads(
        sns.get_topic_attributes(TopicArn=arn)["Attributes"]["Policy"]).get("Statement", [])}


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission refuses an AWSAccountId that is not a 12-digit account id and adds no
    statement; the same label with the caller's own account id is then accepted."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-badacct-"),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    account = arn.split(":")[4]
    label = ctx.unique_name("sim2real-behav-lbl-")
    before = _sids(sns, arn)

    code, message = _error(lambda: sns.add_permission(
        TopicArn=arn, Label=label, AWSAccountId=["not-an-account"], ActionName=["Publish"]))
    assert code == "InvalidParameter", f"AddPermission with a malformed account id gave {code!r}"
    assert message == "Invalid parameter: A provided account ID is not valid", f"unexpected message for a malformed account id: {message!r}"
    assert _sids(sns, arn) == before, "the refused AddPermission must not change the policy"

    sns.add_permission(TopicArn=arn, Label=label, AWSAccountId=[account], ActionName=["Publish"])
    assert _sids(sns, arn) == before | {label}, "the legal AddPermission must add exactly its label"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
