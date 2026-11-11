"""tag-operations-nonexistent-arn-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-operations-nonexistent-arn-not-found"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource and ListTagsForResource on a well-formed own-account monitor ARN that
    does not exist fail with NotFoundException (the model lists ResourceNotFoundException) and the
    exact message, while the same calls on a real monitor succeed."""
    nm = ctx.client("networkmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    real_name = ctx.unique_name("sim2real-nm-tagctl-")
    real_arn = nm.create_monitor(monitorName=real_name, tags={"purpose": "sim2real-tagctl"})["monitorArn"]
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=real_name))

    nm.tag_resource(resourceArn=real_arn, tags={"k": "v"})
    control_tags = nm.list_tags_for_resource(resourceArn=real_arn)["tags"]
    assert control_tags.get("k") == "v", (
        f"positive control: expected tag_resource+list_tags_for_resource to round-trip on a "
        f"real monitor ARN, got {control_tags!r}"
    )
    nm.untag_resource(resourceArn=real_arn, tagKeys=["k"])

    fake_arn = f"arn:aws:networkmonitor:{ctx.region}:{account_id}:monitor/{ctx.unique_name('sim2real-nm-ghost-')}"

    err_list = _error(lambda: nm.list_tags_for_resource(resourceArn=fake_arn))
    assert err_list["Code"] == "NotFoundException", f"expected NotFoundException, got {err_list['Code']!r}"
    expected = "Resource was not found"
    assert err_list["Message"] == expected, f"expected message {expected!r}, got {err_list['Message']!r}"

    err_tag = _error(lambda: nm.tag_resource(resourceArn=fake_arn, tags={"k": "v"}))
    assert err_tag["Code"] == "NotFoundException", f"expected NotFoundException, got {err_tag['Code']!r}"
    expected = "Resource was not found"
    assert err_tag["Message"] == expected, f"expected message {expected!r}, got {err_tag['Message']!r}"

    err_untag = _error(lambda: nm.untag_resource(resourceArn=fake_arn, tagKeys=["k"]))
    assert err_untag["Code"] == "NotFoundException", f"expected NotFoundException, got {err_untag['Code']!r}"
    expected = "Resource was not found"
    assert err_untag["Message"] == expected, f"expected message {expected!r}, got {err_untag['Message']!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
