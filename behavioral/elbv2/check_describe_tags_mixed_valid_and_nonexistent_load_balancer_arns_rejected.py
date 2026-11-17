"""describe-tags-mixed-valid-and-nonexistent-load-balancer-arns-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-tags-mixed-valid-and-nonexistent-load-balancer-arns-rejected"
GROUP = "tagging"
SERVICES = ["elbv2"]

_NOT_FOUND = ("LoadBalancerNotFound", "One or more load balancers not found")


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message); an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code}, got {err.get('Code')}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTags rejects the whole request when one ARN in ResourceArns does not exist,
    even alongside a load balancer ARN that does, and the real ARN's tags stay unchanged."""
    elbv2 = ctx.client("elbv2")
    subnet_ids = ctx.network().subnet_ids[:2]

    name = ctx.unique_name("sim2real-lbtags-")[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "created", "Value": "yes"}],
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn))

    prefix = arn.rsplit("/", 2)[0]
    fake_name = ctx.unique_name("sim2real-nonexistent-lb-")[:32].rstrip("-")
    fake_arn = f"{prefix}/{fake_name}/0123456789abcdef"

    expect_error(
        lambda: elbv2.describe_tags(ResourceArns=[arn, fake_arn]),
        *_NOT_FOUND,
    )

    # The real ARN's tags are untouched by the rejected batched call.
    desc = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]
    tag_map = {t["Key"]: t["Value"] for t in desc["Tags"]}
    assert tag_map == {"created": "yes"}, tag_map


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
