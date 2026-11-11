"""list-tags-for-resources-mixed-types-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-tags-for-resources-mixed-types-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResources rejects a batch holding a ResourceId over the 64-character limit with
    InvalidInput, while a well-formed batch of the same ResourceType succeeds."""
    r53 = ctx.client("route53")

    hc_resp = r53.create_health_check(
        CallerReference=f"sim2real-{uuid.uuid4()}",
        HealthCheckConfig={
            "FullyQualifiedDomainName": "sim2real-hc-target.invalid",
            "Port": 80,
            "Type": "HTTP",
            "ResourcePath": "/",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = hc_resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda: r53.delete_health_check(HealthCheckId=hc_id))

    ok = r53.list_tags_for_resources(ResourceType="healthcheck", ResourceIds=[hc_id])
    got_id = ok["ResourceTagSets"][0]["ResourceId"]
    assert got_id == hc_id, f"expected positive control to return {hc_id!r}, got {got_id!r}"

    # An over-long id fails shape validation before any lookup; a wrong-type or 11th id instead
    # reaches the per-id existence check and yields NoSuchHealthCheck, not InvalidInput.
    overlong_id = "z" * 100
    code, message = _client_error(
        lambda: r53.list_tags_for_resources(
            ResourceType="healthcheck", ResourceIds=[hc_id, overlong_id]
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{overlong_id}' at 'healthCheckId' failed to satisfy "
        "constraint: Member must have length less than or equal to 64"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The healthcheck's own tags are unaffected by the rejected batch call.
    still_ok = r53.list_tags_for_resource(ResourceType="healthcheck", ResourceId=hc_id)
    got_tags = still_ok["ResourceTagSet"]["Tags"]
    assert got_tags == [], f"expected healthcheck tags unaffected by rejected batch, got {got_tags!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
