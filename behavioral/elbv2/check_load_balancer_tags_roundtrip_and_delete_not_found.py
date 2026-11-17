"""load-balancer-tags-roundtrip-and-delete-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "load-balancer-tags-roundtrip-and-delete-not-found"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTags/RemoveTags keep a load balancer's tag set exact — a creation tag survives an
    AddTags, a RemoveTags drops only its key, and removing an absent key is a no-op — then
    DescribeTags on the ARN is refused once DeleteLoadBalancer has removed it."""
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

    def current_tags():
        desc = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]
        return {t["Key"]: t["Value"] for t in desc["Tags"]}

    assert current_tags() == {"created": "yes"}, current_tags()

    elbv2.add_tags(
        ResourceArns=[arn],
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "platform"}],
    )
    assert current_tags() == {"created": "yes", "env": "test", "team": "platform"}, current_tags()

    elbv2.remove_tags(ResourceArns=[arn], TagKeys=["env"])
    assert current_tags() == {"created": "yes", "team": "platform"}, current_tags()

    # Removing a key that was never present succeeds and changes nothing.
    elbv2.remove_tags(ResourceArns=[arn], TagKeys=["does-not-exist"])
    assert current_tags() == {"created": "yes", "team": "platform"}, current_tags()

    elbv2.delete_load_balancer(LoadBalancerArn=arn)

    deadline = time.monotonic() + 120
    while True:
        try:
            elbv2.describe_tags(ResourceArns=[arn])
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) == _NOT_FOUND:
                break
            raise
        else:
            if time.monotonic() >= deadline:
                raise AssertionError("describe_tags on the deleted load balancer still succeeds after 120s")
            time.sleep(3)

    expect_error(lambda: elbv2.describe_tags(ResourceArns=[arn]), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
