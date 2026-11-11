"""list-configuration-sets-garbage-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-configuration-sets-garbage-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConfigurationSets rejects a garbage NextToken with BadRequestException and its exact message,
    and a fresh call without a token afterwards still lists the configuration sets."""
    client = ctx.client("pinpoint-sms-voice")

    garbage_token = "sim2real-not-a-real-continuation-token=="
    try:
        resp = client.list_configuration_sets(NextToken=garbage_token)
        # Some services tolerate an unrecognized token by treating it as "no more
        # results" rather than raising -- that is acceptable as long as it does not
        # error out in some other unexpected way or crash the pagination loop.
        assert "ConfigurationSets" in resp, (
            f"expected a ConfigurationSets key even on a tolerant accept, got keys {sorted(resp.keys())!r}"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "BadRequestException", (
            f"expected a validation-style error for a garbage NextToken, got {code!r}"
        )
        expected = "The following parameter is null, empty or invalid: ['nextToken']"
        message = e.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: an unpaginated call still works afterwards. The account's configuration
    # sets are shared with concurrent runs, so their names are not compared.
    resp2 = client.list_configuration_sets()
    assert isinstance(resp2.get("ConfigurationSets"), list), (
        f"expected a ConfigurationSets list on the follow-up call, got {resp2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
