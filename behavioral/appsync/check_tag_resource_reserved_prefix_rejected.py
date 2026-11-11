"""tag-resource-reserved-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")

CHECK = "tag-resource-reserved-prefix-rejected"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved 'aws:' key prefix must fail BadRequestException, leaving an
    already-applied ordinary tag (the in-file positive control) untouched."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    arn = api["arn"]

    # Positive control: an ordinary tag key in the same shape of call is accepted.
    svc.tag_resource(resourceArn=arn, tags={"sim2real-ok": "yes"})
    tags_after_valid = svc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_valid.get("sim2real-ok") == "yes", f"ordinary tag was not accepted: {tags_after_valid!r}"

    code, msg = _error(lambda: svc.tag_resource(resourceArn=arn, tags={"aws:reserved": "x"}))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert msg == "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)", (
        f"unexpected message: {msg!r}"
    )

    # Effect absent, via an independent read: the reserved-prefix tag never landed, and the
    # earlier valid tag is undisturbed by the rejected call.
    tags_after_rejected = svc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "aws:reserved" not in tags_after_rejected, (
        f"reserved-prefix tag key was stored despite rejection: {tags_after_rejected!r}"
    )
    assert tags_after_rejected.get("sim2real-ok") == "yes", (
        f"prior valid tag was disturbed by the rejected call: {tags_after_rejected!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
