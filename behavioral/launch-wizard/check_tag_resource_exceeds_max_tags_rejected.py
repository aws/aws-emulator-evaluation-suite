"""tag-resource-exceeds-max-tags-rejected."""
from __future__ import annotations
import uuid

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-max-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a UUID-shaped but nonexistent deployment ARN raises NotFoundException "Resource was not
    found" both with more than 200 tags and with a single tag: resource existence is checked first."""
    lw = ctx.client("launch-wizard")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:launchwizard:{ctx.region}:{account_id}:deployment/{uuid.uuid4()}"

    too_many_tags = {f"sim2real-key-{i}": f"value-{i}" for i in range(201)}
    code, message = _client_error(lambda: lw.tag_resource(resourceArn=bogus_arn, tags=too_many_tags))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Resource was not found", f"got message={message!r}"

    # contrast control: the same (UUID-shaped) ARN with a within-bounds tag map fails with
    # the identical not-found code, confirming the oversized map didn't change the outcome
    control_code, control_message = _client_error(
        lambda: lw.tag_resource(resourceArn=bogus_arn, tags={"sim2real-key-0": "value-0"})
    )
    assert control_code == "NotFoundException", (
        f"expected NotFoundException for the within-bounds control, got {control_code!r}"
    )
    assert control_message == "Resource was not found", f"got message={control_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
