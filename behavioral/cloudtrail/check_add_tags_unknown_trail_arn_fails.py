"""add-tags-unknown-trail-arn-fails."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _trail_arn(ctx, name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{name}"


CHECK = "add-tags-unknown-trail-arn-fails"
GROUP = 'error-semantics'
SERVICES = ['cloudtrail']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically valid ARN for a trail that does not exist is a not-found error, not a silent no-op."""
    ct = ctx.client("cloudtrail")
    bogus_name = ctx.unique_name("sim2real-behav-ct-nonexistent-")
    bogus_arn = _trail_arn(ctx, bogus_name)
    account = ctx.client("sts").get_caller_identity()["Account"]

    code, message = _error(
        lambda: ct.add_tags(
            ResourceId=bogus_arn, TagsList=[{"Key": "env", "Value": "fidelity"}]
        )
    )
    assert code == "ResourceNotFoundException", code
    assert message == f"Unknown trail: {bogus_name} for the user: {account}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
