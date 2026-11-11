"""notify-code-configuration-tags-round-trip-and-vanish-on-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notify-code-configuration-tags-round-trip-and-vanish-on-delete"
GROUP = "notify-code-configurations"
SERVICES = ["endusermessaging"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags given at create and by TagResource are listed on a notify code configuration; after
    its delete, ListTagsForResource answers ResourceNotFoundException naming it.
    """
    eum = ctx.client("endusermessaging")
    config = eum.create_notify_code_configuration(
        notifyCodeConfigurationName=ctx.unique_name("sim2real-behav-eum-cctags-"),
        tags=[{"key": "team", "value": "alpha"}]
    )["notifyCodeConfiguration"]
    ccid = config["notifyCodeConfigurationId"]
    ctx.on_cleanup(_teardown(lambda: eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid),
                             "ResourceNotFoundException"))
    arn = config["notifyCodeConfigurationArn"]
    eum.tag_resource(resourceArn=arn, tags=[{"key": "stage", "value": "test"}])
    listed = {t["key"]: t["value"] for t in eum.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert listed == {"team": "alpha", "stage": "test"}, f"tags, got {listed!r}"

    eum.delete_notify_code_configuration(notifyCodeConfigurationId=ccid)
    code, message = _error(lambda: eum.list_tags_for_resource(resourceArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == (
        f'Resource not found - ResourceType="notify-code-configuration" ResourceId="{ccid}"'
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
