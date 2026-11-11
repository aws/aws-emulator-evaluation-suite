"""tag-resource-invalid-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn"
GROUP = 'error-semantics'
SERVICES = ['codecommit']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with a malformed ARN raises InvalidResourceArnException and leaves the repository's
    tags as they were, while tagging the real repository ARN succeeds."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(repositoryName=ctx.unique_name("sim2real-behav-repo-"))["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    arn = meta["Arn"]
    key = ctx.unique_name("sim2real-behav-tagkey-")

    # positive control: tagging a real, well-formed repo ARN succeeds.
    cc.tag_resource(resourceArn=arn, tags={key: "control"})
    tags_after_control = cc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_control.get(key) == "control", tags_after_control

    # negative: a malformed ARN is rejected with the specific error code.
    try:
        cc.tag_resource(resourceArn="not-a-valid-arn", tags={"Key1": "Value1"})
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidResourceArnException", f"expected InvalidResourceArnException, got {code}"
    expected_message = "Inputted resource arn is not formatted correctly."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: an independent read at the destination shows the malformed
    # call touched nothing — the control tag is unchanged and Key1 never landed.
    tags_final = cc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_final.get(key) == "control" and "Key1" not in tags_final, tags_final

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
