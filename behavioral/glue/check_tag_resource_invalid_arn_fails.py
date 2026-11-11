"""tag-resource-invalid-arn-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """tag_resource with a malformed (non-Glue) ARN raises InvalidInputException; a real
    resource can still be tagged, so the rejection is specific to the malformed ARN and not
    every TagResource call."""
    glue = ctx.client("glue")
    try:
        glue.tag_resource(ResourceArn="not-a-valid-arn", TagsToAdd={"k": "v"})
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError("tag_resource with a malformed ARN SUCCEEDED; AWS rejects it")
    code, message = err.get("Code"), err.get("Message")
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for malformed ARN, got {code}"
    )
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same call over a real database ARN succeeds and is visible via
    # get_tags, so the rejection above is specific to the malformed ARN.
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    region = glue.meta.region_name
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_arn = f"arn:aws:glue:{region}:{account_id}:database/{db_name}"

    glue.tag_resource(ResourceArn=resource_arn, TagsToAdd={"k": "v"})
    resp = glue.get_tags(ResourceArn=resource_arn)
    assert resp["Tags"].get("k") == "v", resp["Tags"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
