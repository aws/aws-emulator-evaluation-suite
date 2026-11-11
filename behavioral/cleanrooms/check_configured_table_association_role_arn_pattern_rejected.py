"""configured-table-association-role-arn-pattern-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configured-table-association-role-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfiguredTableAssociation with a roleArn that is not an ARN fails with AccessDeniedException
    "Cross-account pass role is not allowed." and creates no association; the same call with a trusted IAM
    role creates exactly one."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    cr = ctx.client("cleanrooms")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cr-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    db_name, table_name = _create_glue_table(ctx, glue, bucket)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value"],
        analysisMethod="DIRECT_QUERY",
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    membership_ids.append(membership_id)

    assoc_name = "role_pattern_assoc"
    # Long enough to pass the client-side length constraint (fixed min length
    # applies to roleArn), but not a well-formed ARN. Clean Rooms does not
    # validate ARN syntax up front -- it attempts to use the value as
    # a role to assume and the failure surfaces as AccessDeniedException.
    bad_role_arn = "not-an-arn-but-long-enough-to-pass-client-side-length-check-1234567890"
    error = _error(lambda: cr.create_configured_table_association(
        name=assoc_name,
        membershipIdentifier=membership_id,
        configuredTableIdentifier=table_id,
        roleArn=bad_role_arn,
    ))
    assert error["Code"] == "AccessDeniedException", error
    assert error["Message"] == "Cross-account pass role is not allowed.", error

    existing = cr.list_configured_table_associations(membershipIdentifier=membership_id)[
        "configuredTableAssociationSummaries"
    ]
    assert existing == [], f"expected no association after the rejected create, got {existing}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_trusted_role(ctx, iam, account_id, db_name, table_name, bucket)
    association = _create_association_with_retry(
        cr,
        name=assoc_name,
        membershipIdentifier=membership_id,
        configuredTableIdentifier=table_id,
        roleArn=role_arn,
    )
    ctx.on_cleanup(lambda: cr.delete_configured_table_association(
        configuredTableAssociationIdentifier=association["id"], membershipIdentifier=membership_id))

    final = cr.list_configured_table_associations(membershipIdentifier=membership_id)[
        "configuredTableAssociationSummaries"
    ]
    assert len(final) == 1, f"expected exactly one association after the trusted-role create, got {final}"
    assert final[0]["id"] == association["id"], (
        f"listed association id {final[0]['id']!r} does not match created id {association['id']!r}"
    )


def _delete_collaboration_then_memberships(cr, collab_id, membership_ids):
    """The creator's ACTIVE membership cannot be deleted, so the collaboration goes first and
    each membership is deleted once it reads COLLABORATION_DELETED."""
    cr.delete_collaboration(collaborationIdentifier=collab_id)
    for membership_id in membership_ids:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline:
            status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
            if status == "COLLABORATION_DELETED":
                break
            time.sleep(2)
        else:
            raise AssertionError(f"membership {membership_id} never reached COLLABORATION_DELETED: {status}")
        cr.delete_membership(membershipIdentifier=membership_id)


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _create_glue_table(ctx, glue, bucket):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{bucket}/{db_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return db_name, table_name


def _create_trusted_role(ctx, iam, account_id, db_name, table_name, bucket):
    role_name = ctx.unique_name("sim2real-cr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateConfiguredTableAssociation assumes the role and validates it can read the
    # Glue table's schema and underlying S3 location synchronously -- a trust-only
    # role, or one whose Glue table points at a bucket that doesn't exist, gets
    # rejected on every attempt.
    policy_name = "sim2real-cr-glue-read"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"],
                "Resource": [
                    f"arn:aws:glue:{ctx.region}:{account_id}:catalog",
                    f"arn:aws:glue:{ctx.region}:{account_id}:database/{db_name}",
                    f"arn:aws:glue:{ctx.region}:{account_id}:table/{db_name}/{table_name}",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return arn


def _create_association_with_retry(cr, timeout_s: float = 180.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.create_configured_table_association(**kwargs)["configuredTableAssociation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"association never created, likely IAM propagation delay: {last_exc}")


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
