"""get-tags-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-tags-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


def _error(fn):
    """The (code, message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTags on an ARN with no Glue resource-type segment is rejected, while the exact same
    call over a real database ARN still returns that database's own tag map."""
    glue = ctx.client("glue")

    malformed = f"arn:aws:glue:{ctx.region}:{ctx.account}:not-a-resource-type"
    code, message = _error(lambda: glue.get_tags(ResourceArn=malformed))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    assert message == "", f"expected an empty message, got {message!r}"

    db_name = ctx.unique_name("sim2real-behav-db-")
    db_tags = {"stack": "warehouse"}
    glue.create_database(DatabaseInput={"Name": db_name}, Tags=db_tags)
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    db_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:database/{db_name}"

    db_read = glue.get_tags(ResourceArn=db_arn)["Tags"]
    assert db_read == db_tags, f"a real database ARN returned {db_read!r}, expected {db_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
