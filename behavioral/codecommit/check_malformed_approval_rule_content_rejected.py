"""malformed-approval-rule-content-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "malformed-approval-rule-content-rejected"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApprovalRuleTemplate with malformed JSON content raises
    InvalidApprovalRuleTemplateContentException and persists nothing, while a well-formed template in
    minified JSON reads back byte-identical."""
    cc = ctx.client("codecommit")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    good_name = ctx.unique_name("sim2real-behav-cc-art-good-")
    bad_name = ctx.unique_name("sim2real-behav-cc-art-bad-")

    # Already-minified JSON (no insignificant whitespace) — the canonical form CodeCommit
    # stores content in, so this must round-trip byte-identical.
    good_content = (
        '{"Version":"2018-11-08","DestinationReferences":["refs/heads/main"],'
        '"Statements":[{"Type":"Approvers","NumberOfApprovalsNeeded":1,'
        f'"ApprovalPoolMembers":["arn:aws:iam::{account_id}:user/Mary_Major"]}}]}}'
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=good_name, approvalRuleTemplateContent=good_content
    )
    ctx.on_cleanup(lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=good_name))

    # Break exactly one thing: syntactically invalid JSON approval-rule content.
    malformed_content = "{this is not valid json approval rule syntax at all"
    code, message = _error(
        lambda: cc.create_approval_rule_template(
            approvalRuleTemplateName=bad_name, approvalRuleTemplateContent=malformed_content
        )
    )
    assert code == "InvalidApprovalRuleTemplateContentException", (
        f"expected InvalidApprovalRuleTemplateContentException, got {code!r}"
    )
    assert message == (
        "The JSON in the approval rule template is not valid. Review the JSON and make sure "
        "it is valid, and then try again."
    ), message

    # Effect absent: the malformed template must not have been persisted.
    not_found_code, not_found_message = _error(
        lambda: cc.get_approval_rule_template(approvalRuleTemplateName=bad_name)
    )
    assert not_found_code == "ApprovalRuleTemplateDoesNotExistException", (
        f"malformed template should not exist, got lookup code {not_found_code!r}"
    )
    assert not_found_message == (
        "No approval rule template exists in this AWS Region with the following name: "
        f"{bad_name}. Make sure that you are signed in to the AWS Region where you created "
        "the rule, and then try again."
    ), not_found_message

    # Positive control in the same file: the well-formed sibling template is unaffected.
    fetched_good = cc.get_approval_rule_template(approvalRuleTemplateName=good_name)
    actual_good = fetched_good["approvalRuleTemplate"]["approvalRuleTemplateContent"]
    assert actual_good == good_content, f"expected={good_content!r} actual={actual_good!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
