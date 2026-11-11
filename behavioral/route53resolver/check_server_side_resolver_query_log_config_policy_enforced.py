"""server-side-resolver-query-log-config-policy-enforced."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-resolver-query-log-config-policy-enforced"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResolverQueryLogConfigPolicy persists server-side: Get fails before any policy and then
    returns exactly the attached principal, actions and resource.
    """
    r53r = ctx.client("route53resolver")
    sts = ctx.client("sts")
    self_account = sts.get_caller_identity()["Account"]

    log_group_arn = _create_log_group(ctx)
    config = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-behav-qlc-"),
        DestinationArn=log_group_arn,
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
    )["ResolverQueryLogConfig"]
    config_id = config["Id"]
    config_arn = config["Arn"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))

    # AWS answers AccessDeniedException here, not the documented UnknownResourceException.
    before = _error(lambda: r53r.get_resolver_query_log_config_policy(Arn=config_arn))
    expected = ("AccessDeniedException", "[RSLVR-01600] Access denied")
    assert before == expected, f"expected {expected!r} before any policy, got {before!r}"

    # Give the config at least one active association before attempting to share it.
    vpc_id = _create_vpc(ctx)
    assoc = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(r53r, config_id, vpc_id, assoc["Id"]))
    _wait_for_assoc_active(r53r, assoc["Id"])

    actions = [
        "route53resolver:AssociateResolverQueryLogConfig",
        "route53resolver:DisassociateResolverQueryLogConfig",
        "route53resolver:ListResolverQueryLogConfigs",
    ]
    # A nonexistent account principal makes Put fail with InternalServiceErrorException, so the
    # principal is the caller's own account.
    principal_arn = f"arn:aws:iam::{self_account}:root"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": [principal_arn]},
                "Action": actions,
                "Resource": [config_arn],
            }
        ],
    }
    _put_policy_with_retry(r53r, config_arn, json.dumps(policy_doc))

    got = r53r.get_resolver_query_log_config_policy(Arn=config_arn)
    returned = json.loads(got["ResolverQueryLogConfigPolicy"])
    stmt = returned["Statement"][0]
    # AWS returns a one-element Principal.AWS / Resource list as a bare string.
    got_principal = _as_list(stmt["Principal"]["AWS"])
    got_resource = _as_list(stmt["Resource"])
    assert got_principal == [principal_arn], f"expected principal {[principal_arn]!r}, got {got_principal!r}"
    assert sorted(stmt["Action"]) == sorted(actions), f"expected actions {sorted(actions)!r}, got {sorted(stmt['Action'])!r}"
    assert got_resource == [config_arn], f"expected resource {[config_arn]!r}, got {got_resource!r}"


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _as_list(value):
    return [value] if isinstance(value, str) else value


def _put_policy_with_retry(r53r, arn, policy_json, attempts=4):
    import time

    last_err = None
    for i in range(attempts):
        try:
            return r53r.put_resolver_query_log_config_policy(
                Arn=arn, ResolverQueryLogConfigPolicy=policy_json
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "InternalServiceErrorException":
                raise
            last_err = err
            time.sleep(3.0 * (i + 1))
    raise last_err


def _wait_for_assoc_active(r53r, assoc_id, timeout_s=180.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]
        if last["Status"] in ("ACTIVE", "FAILED"):
            assert last["Status"] == "ACTIVE", f"association {assoc_id} reached {last}"
            return last
        time.sleep(2.0)
    raise AssertionError(f"association {assoc_id} never became active, last={last}")


def _disassociate_and_wait(r53r, config_id, vpc_id, assoc_id, timeout_s=180.0):
    """Disassociate, then wait until the association is gone so the config can be deleted."""
    import time

    r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=config_id, ResourceId=vpc_id)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.get_resolver_query_log_config_association(ResolverQueryLogConfigAssociationId=assoc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"association {assoc_id} still present {timeout_s}s after disassociate")
        time.sleep(3.0)


def _create_vpc(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.87.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/sim2real-behav/r53r-")
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]["arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

