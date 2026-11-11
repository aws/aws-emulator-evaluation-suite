"""describe-voices-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-voices-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeVoices rejects a NextToken it never issued with InvalidNextTokenException, while the
    same call without NextToken returns the first page."""
    polly = ctx.client("polly")

    bogus_token = "this-was-never-issued-by-polly=="
    code, message = _error_code(lambda: polly.describe_voices(NextToken=bogus_token))
    assert code == "InvalidNextTokenException", code
    assert message == "Invalid NextToken parameter", message

    # positive control: no token at all works fine
    resp = polly.describe_voices()
    assert resp["Voices"], "expected at least one voice on the first page"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
