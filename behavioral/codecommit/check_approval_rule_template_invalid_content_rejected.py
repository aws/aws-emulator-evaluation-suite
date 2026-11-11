"""approval-rule-template-invalid-content-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "approval-rule-template-invalid-content-rejected"
GROUP = "representation"
SERVICES = ["codecommit"]


def _error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApprovalRuleTemplate with invalid JSON content raises
    InvalidApprovalRuleTemplateContentException and creates nothing, while valid content reads back
    verbatim and is gone after delete."""
    cc = ctx.client("codecommit")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bad_template_name = ctx.unique_name("sim2real-cc-art-bad-")
    invalid_content = "{ this is not valid approval rule template JSON "

    code, message = _error(
        lambda: cc.create_approval_rule_template(
            approvalRuleTemplateName=bad_template_name,
            approvalRuleTemplateContent=invalid_content,
        )
    )
    assert code == "InvalidApprovalRuleTemplateContentException", (
        f"expected InvalidApprovalRuleTemplateContentException for malformed content, got {code!r}"
    )
    expected_message = (
        "The JSON in the approval rule template is not valid. Review the JSON "
        "and make sure it is valid, and then try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no template with that name was created.
    not_found_code, not_found_message = _error(
        lambda: cc.get_approval_rule_template(approvalRuleTemplateName=bad_template_name)
    )
    assert not_found_code == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected the rejected template {bad_template_name!r} to not exist, "
        f"got lookup code {not_found_code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {bad_template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert not_found_message == expected_message, (
        f"expected message {expected_message!r}, got {not_found_message!r}"
    )

    # Positive control: valid JSON content succeeds and is retrievable.
    good_template_name = ctx.unique_name("sim2real-cc-art-good-")
    valid_content = json.dumps(
        {
            "Version": "2018-11-08",
            "DestinationReferences": ["refs/heads/main"],
            "Statements": [
                {
                    "Type": "Approvers",
                    "NumberOfApprovalsNeeded": 1,
                    "ApprovalPoolMembers": [f"arn:aws:sts::{account_id}:assumed-role/Reviewer/*"],
                }
            ],
        }
    )
    cc.create_approval_rule_template(
        approvalRuleTemplateName=good_template_name,
        approvalRuleTemplateContent=valid_content,
    )
    ctx.on_cleanup(
        lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=good_template_name)
    )
    fetched = cc.get_approval_rule_template(approvalRuleTemplateName=good_template_name)
    actual_content = json.loads(fetched["approvalRuleTemplate"]["approvalRuleTemplateContent"])
    expected_content = json.loads(valid_content)
    assert actual_content == expected_content, (
        f"expected the valid template's stored content to parse to {expected_content!r}, "
        f"got {actual_content!r}"
    )

    # Delete proves gone: an independent read on the deleted template now refuses it too.
    cc.delete_approval_rule_template(approvalRuleTemplateName=good_template_name)
    deleted_lookup_code, deleted_lookup_message = _error(
        lambda: cc.get_approval_rule_template(approvalRuleTemplateName=good_template_name)
    )
    assert deleted_lookup_code == "ApprovalRuleTemplateDoesNotExistException", (
        f"expected the deleted template {good_template_name!r} to no longer be found, "
        f"got lookup code {deleted_lookup_code!r}"
    )
    expected_message = (
        "No approval rule template exists in this AWS Region with the following "
        f"name: {good_template_name}. Make sure that you are signed in to the AWS "
        "Region where you created the rule, and then try again."
    )
    assert deleted_lookup_message == expected_message, (
        f"expected message {expected_message!r}, got {deleted_lookup_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

