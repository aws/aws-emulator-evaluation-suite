"""get-federation-token-tags-exceeding-max-count-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-tags-exceeding-max-count-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]


def _tag_list(count: int) -> list[dict]:
    return [{"Key": f"sim2real-tag-{i}", "Value": "v"} for i in range(count)]


def _tag_list_repr(tag_list: list[dict]) -> str:
    """The awsQuery validation error's rendering of a list of Tag structures."""
    rendered = ", ".join(f"Tag(key={t['Key']}, value={t['Value']})" for t in tag_list)
    return f"[{rendered}]"


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; raises AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFederationToken refuses a Tags list one entry past the 50-tag maximum with the exact
    validation message, while 50 tags are still accepted and minted into real credentials."""

    # Client-side parameter validation off, so STS's own input validation answers instead of a
    # local ParamValidationError.
    sts = ctx.client("sts", config=Config(retries={"max_attempts": 1}, parameter_validation=False))

    # Positive control: exactly the maximum of 50 tags is accepted and issues real credentials,
    # isolating the 51st tag below as the one thing the refusal is about.
    at_max = sts.get_federation_token(
        Name=ctx.unique_name("sim2real-behav-fed-"), Tags=_tag_list(50)
    )
    assert at_max["Credentials"]["AccessKeyId"].startswith("ASIA"), (
        f"expected 50 tags to still mint temporary credentials, got "
        f"{at_max['Credentials']['AccessKeyId']!r}"
    )

    over_max = _tag_list(51)
    code, message = _refusal(
        lambda: sts.get_federation_token(
            Name=ctx.unique_name("sim2real-behav-fed-"), Tags=over_max
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for a Tags list one entry past the max, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{_tag_list_repr(over_max)}' at 'tags' failed to "
        "satisfy constraint: Member must have length less than or equal to 50"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
