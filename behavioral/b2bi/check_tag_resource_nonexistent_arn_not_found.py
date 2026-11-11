"""tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a deleted profile's ARN fails with ValidationException and stores no tag,
    while a real resource's ARN can be tagged."""
    b2bi = ctx.client("b2bi")

    resp = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
    )
    profile_id = resp["profileId"]
    real_arn = resp["profileArn"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))

    # A second profile, deleted immediately: its ARN is a genuinely valid, well-formed b2bi
    # ARN (the ID matches the service's real ID format exactly, since AWS itself minted it)
    # but no longer resolves to anything -- isolating "well-formed but gone" from "malformed".
    doomed = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-doomed-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
    )
    doomed_arn = doomed["profileArn"]
    b2bi.delete_profile(profileId=doomed["profileId"])
    assert doomed_arn != real_arn, f"expected distinct profile ARNs, both were {doomed_arn!r}"

    code, message = _error(
        lambda: b2bi.tag_resource(ResourceARN=doomed_arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid input ARN!"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    lookup_code, message = _error(lambda: b2bi.list_tags_for_resource(ResourceARN=doomed_arn))
    assert lookup_code == "ValidationException", f"expected ValidationException, got {lookup_code!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: tagging the real resource's ARN works.
    b2bi.tag_resource(ResourceARN=real_arn, Tags=[{"Key": "k", "Value": "v"}])
    tags = b2bi.list_tags_for_resource(ResourceARN=real_arn)["Tags"]
    assert any(t["Key"] == "k" and t["Value"] == "v" for t in tags), (
        f"expected tag k=v on {real_arn}, got {tags!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
