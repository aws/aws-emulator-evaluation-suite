"""create-load-balancer-missing-permission-denied."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-load-balancer-missing-permission-denied"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLoadBalancer under an explicit identity-policy Deny fails with AccessDenied and
    creates nothing; the same credentials still run an allowed sibling action, full ones succeed."""
    iam = ctx.client("iam")
    elbv2 = ctx.client("elbv2")
    subnet_ids = _default_vpc_subnets(ctx)
    lb_name = ctx.unique_name("sim2real-noperm-")

    user_name = ctx.unique_name("sim2real-elbv2-denied-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "elasticloadbalancing:DescribeLoadBalancers", "Resource": "*"},
            {"Effect": "Deny", "Action": "elasticloadbalancing:CreateLoadBalancer", "Resource": "*"},
        ],
    }
    policy_name = "deny-create-lb"
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=_json(deny_policy))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    restricted = _wait_for_usable_client(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    def _attempt():
        restricted.create_load_balancer(Name=lb_name, Subnets=subnet_ids, Scheme="internal", Type="application")

    code, message = _error(_attempt)
    assert code == "AccessDenied", f"CODE={code!r}"
    lb_resource = f"arn:aws:elasticloadbalancing:{ctx.region}:{ctx.account}:loadbalancer/app/{lb_name}/*"
    expected = (
        f"User: {user_arn} is not authorized to perform: elasticloadbalancing:CreateLoadBalancer "
        f"on resource: {lb_resource} with an explicit deny in an identity-based policy"
    )
    assert message == expected, f"MSG={message!r}"

    # Effect absent: the denied call must not have created anything.
    absence_code, absence_message = _error(lambda: elbv2.describe_load_balancers(Names=[lb_name]))
    assert absence_code == "LoadBalancerNotFound", f"CODE={absence_code!r}"
    assert absence_message == f"Load balancers '[{lb_name}]' not found", f"MSG={absence_message!r}"

    # Scoping: the SAME denied credentials still succeed on the sibling action the identity
    # policy allows, so the earlier AccessDenied is proven specific to CreateLoadBalancer and
    # not a blanket lockout of a freshly-minted principal.
    sibling = restricted.describe_load_balancers()
    assert "LoadBalancers" in sibling, f"sibling action unexpectedly failed: {sibling!r}"

    # Positive control: identical call with full permissions succeeds.
    created = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnet_ids, Scheme="internal", Type="application"
    )["LoadBalancers"][0]
    lb_arn = created["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    # Terminal read: independent of the mutating call, at the destination -- not the
    # CreateLoadBalancer response echoing its own request back.
    described = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert described["LoadBalancerName"] == lb_name, f"NAME={described['LoadBalancerName']!r}"


def _json(obj) -> str:
    import json

    return json.dumps(obj)


def _error(fn) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to attach the load balancer to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 distinct AZs")
    return subnet_ids


def _wait_for_usable_client(ctx, access_key, secret_key, *, timeout_s: float = 45.0):
    """New IAM access keys are eventually consistent; poll sts:GetCallerIdentity (which requires
    no IAM permission at all) until the key is usable, then hand back an elbv2 client signed
    with those same credentials against the same target."""
    deadline = time.monotonic() + timeout_s
    creds = {"aws_access_key_id": access_key, "aws_secret_access_key": secret_key}
    config = Config(retries={"max_attempts": 3})
    sts = ctx.client("sts", config=config, creds=creds)
    last_err = None
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(2)
    else:
        raise AssertionError(f"new access key never became usable within {timeout_s}s: {last_err}")
    return ctx.client("elbv2", config=config, creds=creds)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
