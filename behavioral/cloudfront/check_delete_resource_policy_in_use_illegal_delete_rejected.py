"""delete-resource-policy-in-use-illegal-delete-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-in-use-illegal-delete-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a connection group ARN is rejected with InvalidArgument both while idle
    and while a distribution tenant uses it (a resource-type gate, not an in-use block); a VPC
    origin round-trips Put/GetResourcePolicy as the positive control."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group = cf.create_connection_group(Name=ctx.unique_name("sim2real-cf-cg-"))["ConnectionGroup"]
    group_id = group["Id"]
    group_arn = group["Arn"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, group_id))

    policy_document = json.dumps(_sample_policy(group_arn, account_id, "cloudfront:CreateDistributionTenant"))

    before_code, _ = _error(lambda: cf.get_resource_policy(ResourceArn=group_arn))

    # The group is idle -- nothing has been broken yet. If the gate really is
    # use-based rather than structural, this must succeed.
    idle_code, idle_msg = _error(lambda: cf.put_resource_policy(ResourceArn=group_arn, PolicyDocument=policy_document))
    assert idle_code == "InvalidArgument", f"expected InvalidArgument on an idle connection group, got {idle_code!r}"
    assert idle_msg == "The specified resource type isn't valid. Specify a VPC origin and try again.", (
        f"expected the VPC-origin resource-type gate message, got {idle_msg!r}"
    )

    # Effect-absent: the get-side view of the (never-attached) policy is unchanged.
    after_idle_code, _ = _error(lambda: cf.get_resource_policy(ResourceArn=group_arn))
    assert after_idle_code == before_code, (
        f"GetResourcePolicy view changed after a rejected PutResourcePolicy: "
        f"before={before_code!r} after={after_idle_code!r}"
    )

    dist_id = _create_multitenant_distribution(ctx)
    domain = _domain_name(ctx, "cf-tenant")
    tenant = _create_tenant(ctx, dist_id, domains=[domain], connection_group_id=group_id)
    tenant_id = tenant["Id"]

    # The identical call, now that the group is actively in use by a live
    # tenant: the gate must reject it exactly the same way, proving this is
    # not a conditional, use-based block.
    in_use_code, in_use_msg = _error(
        lambda: cf.put_resource_policy(ResourceArn=group_arn, PolicyDocument=policy_document)
    )
    assert in_use_code == idle_code, (
        f"PutResourcePolicy on the connection group changed once a tenant was attached: "
        f"idle={idle_code!r} in_use={in_use_code!r}"
    )
    assert in_use_msg == idle_msg, (
        f"PutResourcePolicy error message changed once a tenant was attached: "
        f"idle={idle_msg!r} in_use={in_use_msg!r}"
    )

    after_in_use_code, _ = _error(lambda: cf.get_resource_policy(ResourceArn=group_arn))
    assert after_in_use_code == before_code, (
        f"GetResourcePolicy view changed once the group became in-use: "
        f"before={before_code!r} after={after_in_use_code!r}"
    )

    _disable_and_delete_tenant(ctx, tenant_id)

    # Positive control: the one resource type the trio DOES accept -- a VPC
    # origin -- round-trips Put/GetResourcePolicy cleanly on the same
    # CloudFront API, proving the connection-group rejection above is a
    # resource-type gate and not a blanket denial of PutResourcePolicy itself.
    vo_arn = _create_vpc_origin(ctx)
    vo_policy = _sample_policy(vo_arn, account_id, "cloudfront:GetVpcOrigin")
    cf.put_resource_policy(ResourceArn=vo_arn, PolicyDocument=json.dumps(vo_policy))
    ctx.on_cleanup(lambda: _delete_resource_policy(cf, vo_arn))
    stored = json.loads(cf.get_resource_policy(ResourceArn=vo_arn)["PolicyDocument"])
    assert stored == vo_policy, f"expected {vo_policy}, got {stored}"



def _domain_name(ctx, label: str) -> str:
    # CloudFront denylists any *.example.com/.example.org/.example.net domain
    # outright with InvalidArgument ("Domain Name not allowed") -- those roots
    # are IANA-reserved documentation domains. A random, unregistered .com
    # name passes the same format/denylist check without requiring us to own
    # or DNS-validate it.
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _sample_policy(resource_arn: str, principal_account_id: str, action: str) -> dict:
    # PutResourcePolicy rejects a Principal account that does not exist, so this must be a real
    # account. The action must be one the resource type supports (a VPC origin only supports its
    # own read action).
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountGrant",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account_id}:root"},
                "Action": action,
                "Resource": resource_arn,
            }
        ],
    }


def _error(fn):
    """Invoke ``fn`` and return ``(code, message)`` on ClientError. An
    unexpected success raises, so an accepted request can never be read
    as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    origin_id = "sim2real-origin"
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real behavioral fixture (multi-tenant)",
        # CreateDistributionTenant rejects a tenant-only parent that is
        # Enabled=False with InvalidAssociation ("...distribution is
        # disabled"), so this must stay enabled.
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # AWS managed "CachingDisabled"
        },
    }
    dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


#: Not-found codes a teardown step treats as already deleted.
_GONE = ("EntityNotFound", "NoSuchDistribution", "InvalidInstanceID.NotFound")


def _teardown(fn, retry_codes=(), timeout_s: float = 120.0):
    """One teardown step: None on a not-found code, retry ``retry_codes`` (a dependency still
    being released) every 2 s to the deadline, and raise everything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _GONE:
                return None
            if code not in retry_codes or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_distribution_deployed(cf, dist_id, timeout_s: float = 400.0) -> str | None:
    """Poll until the distribution is Deployed and return its ETag; None once it is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        d = _teardown(lambda: cf.get_distribution(Id=dist_id))
        if d is None:
            return None
        if d["Distribution"]["Status"] == "Deployed":
            return d["ETag"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"distribution {dist_id} not Deployed within {timeout_s}s")
        time.sleep(2)


def _delete_distribution(ctx, dist_id) -> None:
    cf = ctx.client("cloudfront")
    if _wait_distribution_deployed(cf, dist_id) is None:
        return
    # A distribution must be disabled before it can be deleted.
    got = _teardown(lambda: cf.get_distribution_config(Id=dist_id))
    if got is None:
        return
    config = got["DistributionConfig"]
    if config.get("Enabled", True):
        config["Enabled"] = False
        _teardown(lambda: cf.update_distribution(Id=dist_id, DistributionConfig=config,
                                                 IfMatch=got["ETag"]))
    etag = _wait_distribution_deployed(cf, dist_id)
    if etag is not None:
        _teardown(lambda: cf.delete_distribution(Id=dist_id, IfMatch=etag), ("ResourceInUse",))


def _create_tenant(ctx, dist_id, domains, connection_group_id=None, name=None, enabled=True):
    cf = ctx.client("cloudfront")
    kwargs = {
        "DistributionId": dist_id,
        "Name": name or ctx.unique_name("sim2real-cf-tenant-"),
        "Domains": [{"Domain": d} for d in domains],
        "Enabled": enabled,
        # CreateDistributionTenant requires a certificate for a custom domain
        # ("There must be at least one certificate
        # ... or a managed certificate request"). "self-hosted" lets the
        # tenant exist with the cert request pending; this check never
        # depends on validation completing.
        "ManagedCertificateRequest": {
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domains[0],
        },
    }
    if connection_group_id:
        kwargs["ConnectionGroupId"] = connection_group_id
    tenant = cf.create_distribution_tenant(**kwargs)["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_tenant(ctx, tenant_id))
    return tenant


def _disable_and_delete_tenant(ctx, tenant_id) -> None:
    cf = ctx.client("cloudfront")
    current = _teardown(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    if current is None:
        return
    if current["DistributionTenant"].get("Enabled"):
        _teardown(lambda: cf.update_distribution_tenant(Id=tenant_id, IfMatch=current["ETag"],
                                                        Enabled=False))
    deadline = time.monotonic() + 240
    while True:
        g = _teardown(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
        if g is None:
            return
        if g["DistributionTenant"]["Status"] == "Deployed":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"distribution tenant {tenant_id} not Deployed within 240s")
        time.sleep(2)
    _teardown(lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=g["ETag"]),
              ("ResourceNotDisabled",))


def _delete_connection_group(ctx, group_id) -> None:
    cf = ctx.client("cloudfront")
    current = _teardown(lambda: cf.get_connection_group(Identifier=group_id))
    if current is None:
        return
    if current["ConnectionGroup"].get("Enabled", True):
        _teardown(lambda: cf.update_connection_group(Id=group_id, IfMatch=current["ETag"],
                                                     Enabled=False), ("ResourceInUse",))

    def delete():
        etag = cf.get_connection_group(Identifier=group_id)["ETag"]
        cf.delete_connection_group(Id=group_id, IfMatch=etag)

    # The group stays in use until its tenant's deletion lands, and disabled once that deploys.
    _teardown(delete, ("ResourceNotDisabled", "CannotDeleteEntityWhileInUse"))


def _delete_resource_policy(cf, resource_arn) -> None:
    _teardown(lambda: cf.delete_resource_policy(ResourceArn=resource_arn))


def _backing_ec2_instance_arn(ctx) -> tuple[str, str]:
    """Launches a minimal, real EC2 instance to back a VPC origin.

    CreateVpcOrigin validates its target ARN synchronously against EC2 (a
    fabricated, syntactically-valid instance ID comes back
    InvalidInstanceID.Malformed), so exercising PutResourcePolicy's one
    currently-supported resource type genuinely requires a live instance
    behind it. Returns ``(arn, instance_id)``.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-cf-rp-backing-")}
                ],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    return arn, instance_id


def _terminate_instance(ctx, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    _teardown(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))


def _create_vpc_origin(ctx) -> str:
    cf = ctx.client("cloudfront")
    arn, instance_id = _backing_ec2_instance_arn(ctx)
    ctx.on_cleanup(lambda: _terminate_instance(ctx, instance_id))
    config = {
        "Name": ctx.unique_name("sim2real-cf-rp-vpcorigin-"),
        "Arn": arn,
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "https-only",
    }
    created = cf.create_vpc_origin(VpcOriginEndpointConfig=config)
    vo_id = created["VpcOrigin"]["Id"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vo_id))
    deployed = _wait_vpc_origin_settled(ctx, vo_id)
    if deployed["Status"] != "Deployed":
        raise AssertionError(f"vpc origin {vo_id} never reached Deployed (status={deployed['Status']!r})")
    return deployed["Arn"]


def _wait_vpc_origin_settled(ctx, vo_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    resp: dict = {}
    while time.monotonic() < deadline:
        resp = cf.get_vpc_origin(Id=vo_id)
        last = resp["VpcOrigin"]["Status"]
        if last != "Deploying":
            return resp["VpcOrigin"]
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vo_id} never left Deploying (last={last!r})")


def _delete_vpc_origin(ctx, vo_id: str) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 400
    while True:
        resp = _teardown(lambda: cf.get_vpc_origin(Id=vo_id))
        if resp is None:
            return
        if resp["VpcOrigin"]["Status"] != "Deploying" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    _teardown(lambda: cf.delete_vpc_origin(Id=vo_id, IfMatch=resp["ETag"]),
              ("CannotDeleteEntityWhileInUse",))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
