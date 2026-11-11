"""tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["timestream-influxdb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against an ARN that does not correspond to any existing resource is
    rejected with ResourceNotFoundException, and tagging a real resource (positive
    control) still succeeds."""
    influx = ctx.client("timestream-influxdb")
    account_id = ctx.account
    bogus_id = "z" * 20
    bogus_arn = f"arn:aws:timestream-influxdb:{ctx.region}:{account_id}:db-parameter-group/{bogus_id}"

    err = _client_error(lambda: influx.tag_resource(resourceArn=bogus_arn, tags={"env": "sim2real"}))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {err['Code']!r}"
    )
    expected_message = "Resource cannot be found."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control: tagging a real resource succeeds. (No DeleteDbParameterGroup API exists for
    # this service, so the group is not cleaned up.)
    name = ctx.unique_name("sim2real-tagnotfound-")
    pg = influx.create_db_parameter_group(name=name)
    influx.tag_resource(resourceArn=pg["arn"], tags={"env": "sim2real"})
    tags = influx.list_tags_for_resource(resourceArn=pg["arn"])["tags"]
    assert tags.get("env") == "sim2real", f"expected tag env=sim2real, got {tags!r}"


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
