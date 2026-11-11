"""presigned-domain-url-expires-after-ttl."""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "presigned-domain-url-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sagemaker"]


# timing:real-time — ttl: 5 s https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreatePresignedDomainUrl.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A presigned domain URL created with a short ExpiresInSeconds window redirects to
    the AWS sign-in page once that window has elapsed, per the documented behavior of
    CreatePresignedDomainUrl, rather than remaining authenticated forever."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    vpc_id, subnet_ids = _get_vpc_subnets(ctx, min_count=1)
    domain_id = _create_domain(ctx, role_arn, vpc_id, subnet_ids)
    _wait_domain_status(ctx, domain_id, "InService")

    user = ctx.unique_name("sim2real-user-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=user)
    ctx.on_cleanup(lambda: _cleanup_user_profile(ctx, domain_id, user))
    _wait_user_profile_status(ctx, domain_id, user, "InService")

    # Fresh URL, used immediately: must land on an authenticated redirect in its own zone.
    fresh_url = sm.create_presigned_domain_url(
        DomainId=domain_id, UserProfileName=user, ExpiresInSeconds=300
    )["AuthorizedUrl"]
    try:
        fresh_ok, fresh_status, fresh_final_url = _is_authenticated(ctx, fresh_url)
    except urllib.error.URLError as exc:
        raise AssertionError(f"no outbound network access to verify presigned URL redirect target: {exc}") from exc
    assert fresh_ok, (
        "a freshly created presigned domain URL should redirect to an authenticated session, "
        f"got status={fresh_status} final_url={fresh_final_url}"
    )

    # A second URL created with the minimum ExpiresInSeconds (5s) - only used once,
    # after the window has elapsed, to avoid conflating expiry with any potential
    # single-use semantics of the URL.
    ttl_s = 5
    created_at = time.monotonic()
    stale_url = sm.create_presigned_domain_url(
        DomainId=domain_id, UserProfileName=user, ExpiresInSeconds=ttl_s
    )["AuthorizedUrl"]
    # Wait out the TTL (net of time already spent), then bound-retry for up to 4x the 5s
    # minimum window rather than asserting once at a fixed delay.
    remaining = max(0.0, ttl_s - (time.monotonic() - created_at))
    if remaining > 0:
        time.sleep(remaining)
    stale_ok, stale_status, stale_final_url = _poll_until(
        lambda: _is_authenticated(ctx, stale_url),
        lambda result: not result[0],
        timeout_s=_budget_s(ctx, 4 * ttl_s),
        interval_s=2.0,
        ctx=ctx,
    )
    assert not stale_ok, (
        "a presigned domain URL used after ExpiresInSeconds elapsed should no longer authenticate, "
        f"got status={stale_status} final_url={stale_final_url}"
    )



def _same_zone(final_url, presigned_url) -> bool:
    """Whether a redirect chain ended in the presigned URL's own zone: every host label after the
    first (service label, region, domain) is the presigned host's. A hand-off to a sign-in page
    on another host is not, and the domain is compared, never named."""
    final = (urlsplit(final_url or "").hostname or "").split(".")
    origin = (urlsplit(presigned_url).hostname or "").split(".")
    return len(origin) > 2 and all(origin) and final[1:] == origin[1:]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe: Any, predicate: Any, *, timeout_s: float, interval_s: float, ctx: Any = None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _is_authenticated(ctx, url: str, timeout: float = 15.0) -> tuple[bool, int, str]:
    # The Studio auth redirect chain sets a session cookie on one hop and expects it back on
    # the next (a different host, studio-d-*.studio.<region>.sagemaker.aws); a plain urlopen()
    # with no cookie jar drops it and the final hop 403s even though the domain redirect itself
    # succeeded, which reads as "unauthenticated" for the wrong reason.
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    req = _routed_request(ctx, url, headers={"User-Agent": "sim2real-behavioral-check/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            final_url, status = resp.geturl(), resp.status
    except urllib.error.HTTPError as exc:
        final_url, status = exc.geturl(), exc.code
    ok = status < 400 and _same_zone(final_url, url)
    return ok, status, final_url


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role["Arn"]


def _get_vpc_subnets(ctx: Any, min_count: int = 1) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets[:min_count]]
        if len(subnet_ids) >= min_count:
            return vpc_id, subnet_ids
    vpc = ec2.create_vpc(
        CidrBlock="10.194.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(min_count):
        az = azs[i % len(azs)]["ZoneName"]
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.194.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _retry(fn, attempts: int = 12, delay: float = 15.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _create_domain(ctx: Any, role_arn: str, vpc_id: str, subnet_ids: list[str]) -> str:
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-domain-")
    resp = sm.create_domain(
        DomainName=name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        SubnetIds=subnet_ids,
        VpcId=vpc_id,
    )
    domain_id = resp["DomainId"]
    ctx.on_cleanup(lambda: _cleanup_domain(ctx, domain_id))
    return domain_id


def _cleanup_domain(ctx: Any, domain_id: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_domain(DomainId=domain_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            sm.describe_domain(DomainId=domain_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(3)


def _cleanup_user_profile(ctx: Any, domain_id: str, user: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_user_profile(DomainId=domain_id, UserProfileName=user)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            sm.describe_user_profile(DomainId=domain_id, UserProfileName=user)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(3)


def _wait_domain_status(ctx: Any, domain_id: str, want: str, timeout_s: float = 1200.0, interval_s: float = 2.0) -> None:
    sm = ctx.client("sagemaker")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status == want:
            return
        if status in ("Failed", "Delete_Failed", "Update_Failed"):
            raise AssertionError(f"domain entered {status} while waiting for {want}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain to reach {want}: the run budget ended first; not graded")
    raise AssertionError(f"domain did not reach {want} within {timeout_s}s")


def _wait_user_profile_status(ctx: Any, domain_id: str, user: str, want: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    sm = ctx.client("sagemaker")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_user_profile(DomainId=domain_id, UserProfileName=user)["Status"]
        if status == want:
            return
        if status in ("Failed", "Delete_Failed", "Update_Failed"):
            raise AssertionError(f"user profile entered {status} while waiting for {want}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"user profile to reach {want}: the run budget ended first; not graded")
    raise AssertionError(f"user profile did not reach {want} within {timeout_s}s")


# Resources in a VPC delete asynchronously: their AWS-managed ENIs linger in the subnet / security
# group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails DependencyViolation.
# Teardown waits (bounded, one window shared by all network deletes) for the ENIs to go, retries
# DependencyViolation, and finally raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(3)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(3)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
