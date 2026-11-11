"""query-log-config-association-state-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-log-config-association-state-transition"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A query log config association reaches ACTIVE via GetResolverQueryLogConfigAssociation.

    DisassociateResolverQueryLogConfig then removes it so it is no longer found.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    r53r = ctx.client("route53resolver")
    account_id = sts.get_caller_identity()["Account"]

    vpc_id = _create_vpc(ctx, ec2)

    bucket_name, bucket_arn = _create_query_log_bucket(ctx, s3, account_id)

    config_id = r53r.create_resolver_query_log_config(
        Name=ctx.unique_name("sim2real-qlc-"),
        DestinationArn=bucket_arn,
        CreatorRequestId=ctx.unique_name("sim2real-qlc-cr-"),
    )["ResolverQueryLogConfig"]["Id"]
    ctx.on_cleanup(lambda: r53r.delete_resolver_query_log_config(ResolverQueryLogConfigId=config_id))

    config_status = _poll_until(
        lambda: r53r.get_resolver_query_log_config(ResolverQueryLogConfigId=config_id)[
            "ResolverQueryLogConfig"
        ]["Status"],
        lambda s: s in ("CREATED", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert config_status == "CREATED", f"query log config reached {config_status!r} instead of CREATED"

    assoc = r53r.associate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
    )["ResolverQueryLogConfigAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(r53r, config_id, vpc_id, assoc_id))

    status = _poll_until(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )["ResolverQueryLogConfigAssociation"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert status == "ACTIVE", f"association reached {status!r} instead of ACTIVE"

    # Filtered by Id: an unfiltered List is one unpaginated page, and unrelated
    # associations in the account could push this one off it.
    listed = r53r.list_resolver_query_log_config_associations(
        Filters=[{"Name": "Id", "Values": [assoc_id]}]
    )["ResolverQueryLogConfigAssociations"]
    assert any(a["Id"] == assoc_id for a in listed), (
        "association missing from ListResolverQueryLogConfigAssociations"
    )

    r53r.disassociate_resolver_query_log_config(
        ResolverQueryLogConfigId=config_id, ResourceId=vpc_id
    )
    _poll_until(
        lambda: _still_present(
            lambda: r53r.get_resolver_query_log_config_association(
                ResolverQueryLogConfigAssociationId=assoc_id
            )
        ),
        lambda still: not still,
        timeout_s=120,
        interval_s=5,
    )
    code, message = _error(
        lambda: r53r.get_resolver_query_log_config_association(
            ResolverQueryLogConfigAssociationId=assoc_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "[RSLVR-01602] The specified query logging configuration association doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    remaining = r53r.list_resolver_query_log_config_associations(
        Filters=[{"Name": "Id", "Values": [assoc_id]}]
    )["ResolverQueryLogConfigAssociations"]
    assert not any(a["Id"] == assoc_id for a in remaining), "disassociated config still listed"


def _create_vpc(ctx, ec2):
    """A VPC this check owns, deleted at teardown after the association is gone."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


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


def _still_present(fn) -> bool:
    """True while fn() succeeds; False once it raises ResourceNotFoundException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise
    return True


def _disassociate_and_wait(r53r, config_id: str, vpc_id: str, assoc_id: str) -> None:
    """Teardown: disassociate if the check did not, then wait until the association is gone."""
    try:
        r53r.disassociate_resolver_query_log_config(ResolverQueryLogConfigId=config_id, ResourceId=vpc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("ResourceNotFoundException", "InvalidRequestException"):
            raise
    _poll_until(
        lambda: _still_present(
            lambda: r53r.get_resolver_query_log_config_association(ResolverQueryLogConfigAssociationId=assoc_id)
        ),
        lambda still: not still,
        timeout_s=180,
        interval_s=5,
    )


def _create_query_log_bucket(ctx, s3, account_id):
    bucket_name = ctx.unique_name("sim2real-r53r-qlc-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-query-log-delivery",
        "Statement": [
            {
                "Sid": "AllowQueryLogDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
            },
            {
                "Sid": "AllowQueryLogAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    return bucket_name, f"arn:aws:s3:::{bucket_name}"


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
