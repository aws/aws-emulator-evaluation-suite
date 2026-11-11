"""get-configured-table-association-analysis-rule-not-found-before-creation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-configured-table-association-analysis-rule-not-found-before-creation"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A configured table association can exist without an analysis rule --
    GetConfiguredTableAssociationAnalysisRule raises ResourceNotFoundException
    until one is created, after which the same call succeeds."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    cr = ctx.client("cleanrooms")

    account_id = sts.get_caller_identity()["Account"]
    db_name, table_name, bucket_name = _create_glue_table(ctx, glue, s3)
    role_arn = _create_trusted_role(ctx, iam, account_id, ctx.region, db_name, table_name, bucket_name)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value"],
        analysisMethod="DIRECT_QUERY",
        tags={"sim2real": CHECK},
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"joinColumns": ["id"], "listColumns": ["value"]}}},
    )

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["collaboration"]["id"]
    memberships: list[str] = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, memberships))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED", tags={"sim2real": CHECK}
    )["membership"]["id"]
    memberships.append(membership_id)

    association = _create_association_with_retry(
        cr,
        name="assoc_no_rule_yet",
        membershipIdentifier=membership_id,
        configuredTableIdentifier=table_id,
        roleArn=role_arn,
        tags={"sim2real": CHECK},
    )
    assoc_id = association["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table_association(
        configuredTableAssociationIdentifier=assoc_id, membershipIdentifier=membership_id))

    def _get_rule():
        return cr.get_configured_table_association_analysis_rule(
            membershipIdentifier=membership_id,
            configuredTableAssociationIdentifier=assoc_id,
            analysisRuleType="LIST",
        )

    # AWS names the LIST rule type by its internal name, IntersectionList.
    expected_message = (
        f"No such analysis rule with configuredTableAssociationId: {assoc_id} and type "
        f"IntersectionList"
    )
    code_before, message_before = _error(_get_rule)
    assert code_before == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException before the analysis rule is created, got {code_before!r}"
    )
    assert message_before == expected_message, (
        f"expected message {expected_message!r} before the analysis rule is created, "
        f"got {message_before!r}"
    )

    cr.create_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"allowedResultReceivers": [account_id]}}},
    )

    now_present = _get_rule()["analysisRule"]
    assert now_present["type"] == "LIST", (
        f"expected type LIST on the newly created analysis rule, got {now_present.get('type')!r}"
    )

    cr.delete_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="LIST",
    )
    code_after_delete, message_after_delete = _error(_get_rule)
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after the analysis rule is deleted, got {code_after_delete!r}"
    )
    assert message_after_delete == expected_message, (
        f"expected message {expected_message!r} after the analysis rule is deleted, "
        f"got {message_after_delete!r}"
    )


def _create_glue_table(ctx, glue, s3):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    bucket_name = ctx.unique_name("sim2real-cr-bkt-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint, not a region pin
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    key = f"{db_name}/data.csv"
    s3.put_object(Bucket=bucket_name, Key=key, Body=b"id,value\n1,a\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key=key))

    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{bucket_name}/{db_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return db_name, table_name, bucket_name


def _create_trusted_role(ctx, iam, account_id, region, db_name, table_name, bucket_name):
    role_name = ctx.unique_name("sim2real-cr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # CreateConfiguredTableAssociation validates the role's access to the underlying Glue
    # table before it will accept it -- with no policy at all it AccessDenied's forever, which
    # looks like (but is not) IAM propagation delay.
    policy_name = "sim2real-cr-table-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"],
                    "Resource": [
                        f"arn:aws:glue:{region}:{account_id}:catalog",
                        f"arn:aws:glue:{region}:{account_id}:database/{db_name}",
                        f"arn:aws:glue:{region}:{account_id}:table/{db_name}/{table_name}",
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return arn


def _create_association_with_retry(cr, timeout_s: float = 480.0, **kwargs):
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
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator answering a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
