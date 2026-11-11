"""tag-resource-unknown-arn-rejected."""
from __future__ import annotations

CHECK = "tag-resource-unknown-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against a well-formed but non-existent tunnel ARN is rejected, real ARNs still work."""
    client = ctx.client("iotsecuretunneling")

    opened = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-"))
    tunnel_id = opened["tunnelId"]
    real_arn = opened["tunnelArn"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    bogus_arn = real_arn[: real_arn.rfind("/") + 1] + ctx.unique_name("nonexistent-tunnel-")
    assert bogus_arn != real_arn, f"bogus ARN must differ from the real one, got {bogus_arn!r} == {real_arn!r}"

    bogus_id = bogus_arn[bogus_arn.rfind("/") + 1 :]
    expected_message = f"Tunnel {bogus_id} does not exist."

    code, message = _error(lambda: client.tag_resource(resourceArn=bogus_arn, tags=[{"key": "k", "value": "v"}]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException tagging a nonexistent ARN, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no tag ended up anywhere retrievable for the bogus ARN.
    absent_code, absent_message = _error(lambda: client.list_tags_for_resource(resourceArn=bogus_arn))
    assert absent_code == "ResourceNotFoundException", f"expected ResourceNotFoundException listing tags for a nonexistent ARN, got {absent_code!r}"
    assert absent_message == expected_message, f"expected message {expected_message!r}, got {absent_message!r}"

    # Positive control: tagging the real tunnel ARN succeeds.
    client.tag_resource(resourceArn=real_arn, tags=[{"key": "k", "value": "v"}])
    tags_now = {t["key"]: t["value"] for t in client.list_tags_for_resource(resourceArn=real_arn)["tags"]}
    assert tags_now.get("k") == "v", f"expected tag k=v on the real tunnel ARN, got {tags_now!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
