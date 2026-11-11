"""db-proxy-modify-while-creating-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-proxy-modify-while-creating-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh proxies tried before the check gives up on observing the creating window.
_ATTEMPTS = 3
#: Bound on retrying CreateDBProxy while a new role's trust is still propagating.
_IAM_PROPAGATION_TIMEOUT_S = 90.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyDBProxy on a proxy still creating is refused with InvalidDBProxyStateFault and its exact
    message, and the refused change leaves the proxy's RequireTLS unset."""
    rds = ctx.client("rds")
    subnet_ids = _subnets(ctx)
    secret_arn = _secret(ctx)
    role_arn = _role(ctx, secret_arn)

    tried = []
    proxy = None
    for _ in range(_ATTEMPTS):
        candidate = ctx.unique_name("sim2real-proxymod-")
        ctx.on_cleanup(lambda p=candidate: _drop_proxy(rds, p))
        created = _create_proxy(rds, candidate, role_arn, secret_arn, subnet_ids)
        assert created["Status"] == "creating", (
            f"CreateDBProxy answered Status {created['Status']!r}, expected 'creating'"
        )
        before = _proxy(rds, candidate)["Status"]
        if before != "creating":
            tried.append(f"{candidate}: read {before!r} before the modify")
            continue
        code, message = _outcome(lambda: rds.modify_db_proxy(DBProxyName=candidate, RequireTLS=True))
        expected = f"DB Proxy {candidate} is in an unsupported state - CREATING, needs to be in [ACTIVE]"
        if (code, message) == ("InvalidDBProxyStateFault", expected):
            proxy = candidate
            break
        after = _proxy(rds, candidate)["Status"]
        assert after != "creating", (
            f"ModifyDBProxy on a creating proxy answered {code!r} {message!r}; expected "
            f"InvalidDBProxyStateFault {expected!r}"
        )
        assert code == _ACCEPTED, f"ModifyDBProxy answered {code!r} {message!r} once the proxy was {after!r}"
        tried.append(f"{candidate}: modify accepted after the proxy left creating ({after!r})")
    assert proxy, f"ModifyDBProxy was never refused while creating in {_ATTEMPTS} proxies: {tried!r}"

    require_tls = _proxy(rds, proxy).get("RequireTLS")
    assert require_tls is False, f"the refused ModifyDBProxy left RequireTLS {require_tls!r}, expected False"


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _proxy(rds, name: str) -> dict:
    return rds.describe_db_proxies(DBProxyName=name)["DBProxies"][0]


def _subnets(ctx) -> list[str]:
    """One subnet in each of two availability zones of the shared network."""
    net = ctx.network()
    subnets = ctx.client("ec2").describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [net.vpc_id]}, {"Name": "subnet-id", "Values": net.subnet_ids},
    ])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    assert len(by_az) >= 2, f"the shared network offers subnets in {sorted(by_az)!r}; a proxy needs two AZs"
    return [by_az[az] for az in sorted(by_az)[:2]]


def _secret(ctx) -> str:
    sm = ctx.client("secretsmanager")
    arn = sm.create_secret(
        Name=ctx.unique_name("sim2real-proxymod-secret-"),
        SecretString=json.dumps({"username": "admin", "password": "Sim2RealTmpPwd123!"}),
        Tags=_TAGS,
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


def _role(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-proxymod-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)["Role"]["Arn"]
    policy = "sim2real-proxymod-secret-access"

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName=policy)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    iam.put_role_policy(RoleName=name, PolicyName=policy, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }))
    return arn


def _create_proxy(rds, name: str, role_arn: str, secret_arn: str, subnet_ids: list[str]) -> dict:
    """CreateDBProxy, retrying the InvalidParameterValue naming the role that a just-created role
    answers until IAM propagates it; any other refusal raises."""
    deadline = time.monotonic() + _IAM_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return rds.create_db_proxy(
                DBProxyName=name, EngineFamily="MYSQL", RoleArn=role_arn, VpcSubnetIds=subnet_ids,
                Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
                Tags=_TAGS,
            )["DBProxy"]
        except ClientError as exc:
            err = exc.response["Error"]
            message = (err.get("Message") or "").lower()
            propagating = err["Code"] == "InvalidParameterValue" and "role" in message
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _drop_proxy(rds, name: str, timeout_s: float = 1500.0) -> None:
    """Delete the proxy once it leaves creating and wait until it is gone, so its network
    interfaces are released before the shared network is torn down; gone counts as deleted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = _proxy(rds, name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBProxyNotFoundFault":
                return
            raise
        if status not in ("creating", "deleting"):
            try:
                rds.delete_db_proxy(DBProxyName=name)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "DBProxyNotFoundFault":
                    return
                if code != "InvalidDBProxyStateFault":
                    raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"DB proxy {name} still {status!r} after {timeout_s:.0f}s; not gone")
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
