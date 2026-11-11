"""concurrent-create-db-proxy-duplicate-name-single-winner."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-db-proxy-duplicate-name-single-winner"
GROUP = "concurrency"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-proxy"},
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateDBProxy calls with the same name create exactly one proxy; the loser
    gets DBProxyAlreadyExistsFault with its exact message and no duplicate proxy exists."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available to provision the DB proxy prerequisite network"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least two availability zones")

    secret_name = ctx.unique_name("sim2real-rdsproxy-secret-")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "admin", "password": "Sim2RealTmpPwd123!"}),
        Tags=_MANAGED_TAGS,
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_name = ctx.unique_name("sim2real-rdsproxy-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_MANAGED_TAGS,
    )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    policy_name = "sim2real-rdsproxy-secret-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )

    def _cleanup_role() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if _error_code_from(exc) != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    proxy_name = _sanitize_db_proxy_name(ctx.unique_name("sim2real-proxy-"))
    ctx.on_cleanup(lambda: _delete_proxy_if_exists(rds, proxy_name))

    successes: list[dict] = []
    failures: list[ClientError] = []

    def _create():
        # IAM is eventually consistent: CreateDBProxy can return InvalidParameterValue for a few
        # seconds after the role/policy are created, so retry (bounded) instead of a fixed sleep.
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
        deadline = time.monotonic() + 90.0
        while True:
            try:
                return rds.create_db_proxy(
                    DBProxyName=proxy_name,
                    EngineFamily="MYSQL",
                    RoleArn=role_arn,
                    VpcSubnetIds=subnet_ids,
                    Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
                    Tags=_MANAGED_TAGS,
                )
            except ClientError as exc:
                if _error_code_from(exc) == "InvalidParameterValue" and time.monotonic() < deadline:
                    time.sleep(5)
                    continue
                raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        for fut in futures:
            try:
                successes.append(fut.result())
            except ClientError as exc:
                failures.append(exc)

    assert len(successes) == 1, f"expected exactly one CreateDBProxy to succeed, got {len(successes)}"
    assert len(failures) == 1, f"expected exactly one CreateDBProxy to be rejected, got {len(failures)}"
    code = _error_code_from(failures[0])
    assert code == "DBProxyAlreadyExistsFault", f"unexpected loser error code: {code}"
    message = failures[0].response["Error"].get("Message")
    # AWS words the refusal in two exact forms depending on where the duplicate is caught.
    expected = (f"The DBProxy '{proxy_name}' already exists", f"DBProxy '{proxy_name}' already exists")
    assert message in expected, f"unexpected loser message: {message!r} (expected one of {expected!r})"

    proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
    assert len(proxies) == 1, f"expected exactly one proxy to exist, found {len(proxies)}"


def _error_code_from(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]


def _sanitize_db_proxy_name(name: str) -> str:
    """Collapse consecutive hyphens and strip a trailing hyphen so the value satisfies
    DBProxyName's ^[a-zA-Z](?:-?[a-zA-Z0-9]+)*$ pattern regardless of ctx.unique_name's shape."""
    out = []
    prev_hyphen = False
    for ch in name:
        is_hyphen = ch == "-"
        if is_hyphen and prev_hyphen:
            continue
        out.append(ch)
        prev_hyphen = is_hyphen
    sanitized = "".join(out).rstrip("-")
    if not sanitized or not sanitized[0].isalpha():
        sanitized = "p" + sanitized
    return sanitized


def _delete_proxy_if_exists(rds, name: str, timeout_s: float = 900.0) -> None:
    """Delete the proxy once it leaves 'creating'; not-found is clean, every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            proxies = rds.describe_db_proxies(DBProxyName=name)["DBProxies"]
        except ClientError as exc:
            if _error_code_from(exc) == "DBProxyNotFoundFault":
                return
            raise
        if not proxies:
            return
        if proxies[0]["Status"] != "creating":
            try:
                rds.delete_db_proxy(DBProxyName=name)
                return
            except ClientError as exc:
                code = _error_code_from(exc)
                if code == "DBProxyNotFoundFault":
                    return
                if code != "InvalidDBProxyStateFault" or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"DB proxy {name} still 'creating' after {timeout_s}s; not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
