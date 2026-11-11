"""put-resource-policy-arn-validation-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-arn-validation-boundary"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]
ARN_PATTERN = r"^arn:[\w+=/,.@-]+:aws-marketplace:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy refuses a malformed ARN with ValidationException and its exact message and a
    well-formed ARN of an entity the caller does not own with AccessDeniedException, and
    GetResourcePolicy on that ARN is denied as well.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")
    policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"aws-marketplace:ViewSubscriptions","Resource":"*"}]}'

    code, msg = _error_code(lambda: mp.put_resource_policy(ResourceArn="short-and-bad", Policy=policy))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {msg}"
    assert msg == (
        f"[Requested resource arn 'short-and-bad' is invalid. It should match with {ARN_PATTERN}.]"
    ), msg

    missing_arn = (
        "arn:aws:aws-marketplace:us-east-1:111122223333:AWSMarketplace/AmiProduct/"
        + ctx.unique_name("sim2real-behav-")
    )
    # message varies: AWS embeds the calling principal's ARN, which the check does not create.
    code2, msg2 = _error_code(lambda: mp.put_resource_policy(ResourceArn=missing_arn, Policy=policy))
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}: {msg2}"

    # message varies: AWS embeds the calling principal's ARN, which the check does not create.
    code3, msg3 = _error_code(lambda: mp.get_resource_policy(ResourceArn=missing_arn))
    assert code3 == "AccessDeniedException", f"no policy should have been stored, got {code3}: {msg3}"

    # positive control: the service is still reachable and functioning, so the three
    # rejections above are specific to these calls, not the client/connection being broken
    resp = mp.list_change_sets(Catalog="AWSMarketplace")
    assert "ChangeSetSummaryList" in resp


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
