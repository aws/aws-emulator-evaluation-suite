"""identity-source-error-on-nonexistent-sso-instance."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-source-error-on-nonexistent-sso-instance"
GROUP = "overly-permissive"
SERVICES = ["mpa"]
INVALID_ARN = ("ValidationException", "Invalid IdentitySourceArn.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIdentitySource and DeleteIdentitySource refuse a UUID identifier that does not match the
    IdentitySourceId shape with the identical ValidationException before any existence check, while
    ListIdentitySources returns a page.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:mpa:us-east-1:{account}:identity-source/{uuid.uuid4()}"

    get_err = _error(lambda: mpa.get_identity_source(IdentitySourceArn=bogus_arn))
    assert get_err == INVALID_ARN, get_err

    delete_err = _error(lambda: mpa.delete_identity_source(IdentitySourceArn=bogus_arn))
    assert delete_err == INVALID_ARN, delete_err

    # positive control: a plain list (no resource reference) is otherwise good
    resp = mpa.list_identity_sources(MaxResults=20)
    assert "IdentitySources" in resp, f"expected an IdentitySources page, got {resp!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
