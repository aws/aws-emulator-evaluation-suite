"""list-tags-for-resources-mixed-valid-invalid-fails-whole-batch."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resources-mixed-valid-invalid-fails-whole-batch"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Including one nonexistent hosted-zone id alongside a valid one in a
    ListTagsForResources batch fails the whole call with NoSuchHostedZone --
    it does not partially succeed and silently drop the bad id."""
    route53 = ctx.client("route53")

    full_id = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.zone-mixed-test.com",
        CallerReference=str(uuid.uuid4()),
    )["HostedZone"]["Id"]
    valid_id = _zone_id(full_id)
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=full_id))
    route53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=valid_id,
        AddTags=[{"Key": "purpose", "Value": "mixed-batch-check"}],
    )

    bogus_id = "Z00000000000000000000"

    code, message = _client_error(
        lambda: route53.list_tags_for_resources(
            ResourceType="hostedzone", ResourceIds=[valid_id, bogus_id]
        )
    )
    assert code == "NoSuchHostedZone", f"expected NoSuchHostedZone, got {code!r}"
    expected_message = f"No hosted zone found with ID: {bogus_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the same valid id alone succeeds and carries its tag --
    # proving the failure above was about the bogus id, not the valid one.
    resp = route53.list_tags_for_resources(ResourceType="hostedzone", ResourceIds=[valid_id])
    assert len(resp["ResourceTagSets"]) == 1, (
        f"expected exactly 1 ResourceTagSet for the solo valid id, got {resp['ResourceTagSets']!r}"
    )
    tags = {t["Key"]: t["Value"] for t in resp["ResourceTagSets"][0]["Tags"]}
    assert tags.get("purpose") == "mixed-batch-check", (
        f"expected tag purpose='mixed-batch-check', got tags={tags!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _zone_id(full_id: str) -> str:
    return full_id.rsplit("/", 1)[-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
