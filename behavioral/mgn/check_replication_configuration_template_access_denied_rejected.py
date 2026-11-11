"""replication-configuration-template-access-denied-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-configuration-template-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "requires:mgn-initialized")
def run(ctx) -> None:
    """CreateReplicationConfigurationTemplate from an IAM identity with no policies is rejected
    with AccessDeniedException naming the denied action, and creates no template; once granted
    exactly that permission, the identical call has the privileged identity's outcome."""
    mgn = ctx.client("mgn")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    _ensure_initialized(mgn)

    subnets = ec2.describe_subnets(MaxResults=5).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in this account/region to run the check")
    subnet_id = subnets[0]["SubnetId"]

    template_params = dict(
        stagingAreaSubnetId=subnet_id,
        associateDefaultSecurityGroup=True,
        replicationServersSecurityGroupsIDs=[],
        replicationServerInstanceType="t3.small",
        useDedicatedReplicationServer=False,
        defaultLargeStagingDiskType="GP3",
        ebsEncryption="DEFAULT",
        bandwidthThrottling=0,
        dataPlaneRouting="PRIVATE_IP",
        createPublicIP=False,
        stagingAreaTags={"sim2real-check": CHECK},
    )

    created_ids = []
    last_error = {}

    def _delete_created():
        while created_ids:
            mgn.delete_replication_configuration_template(
                replicationConfigurationTemplateID=created_ids[-1]
            )
            created_ids.pop()

    ctx.on_cleanup(_delete_created)

    def _outcome(client):
        """The call's outcome: "created" when it creates a template, else its error code."""
        last_error.clear()
        try:
            resp = client.create_replication_configuration_template(**template_params)
        except ClientError as e:
            last_error["error"] = e.response.get("Error", {})
            return e.response["Error"]["Code"]
        created_ids.append(resp["replicationConfigurationTemplateID"])
        return "created"

    def _template_ids():
        items = mgn.describe_replication_configuration_templates().get("items", [])
        return {t["replicationConfigurationTemplateID"] for t in items}

    # Baseline: the account's quota admits one replication configuration template, so once it
    # holds one the privileged identity's identical call meets the quota. The check makes its
    # own only when the account holds none, and deletes only templates it made.
    if not _template_ids():
        assert _outcome(mgn) == "created", (
            f"the privileged identity must create the account's first template, got "
            f"{last_error.get('error')!r}"
        )
    quota_message = "Max Replication Configuration Templates per Account exceeded"
    baseline = _outcome(mgn)
    assert baseline == "ServiceQuotaExceededException", (
        f"expected the privileged identity's second template to meet the quota, got "
        f"{baseline!r} ({last_error.get('error')!r})"
    )
    assert last_error["error"].get("Message") == quota_message, (
        f"expected quota message {quota_message!r}, got {last_error['error'].get('Message')!r}"
    )

    user_name = ctx.unique_name("sim2real-mgn-rctnoperm-")
    user = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    user_arn = user["User"]["Arn"]
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    unpriv_mgn = ctx.client(
        "mgn",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    ids_before = _template_ids()

    # IAM credential propagation can lag by a few seconds; poll for the expected rejection.
    seen = None
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        seen = _outcome(unpriv_mgn)
        if seen == "AccessDeniedException":
            break
        time.sleep(3.0)

    assert seen != "created", "an unauthorized identity must never be able to create a template"
    assert seen == "AccessDeniedException", (
        f"expected AccessDeniedException for an unauthorized identity, got {seen!r}"
    )
    partition = user_arn.split(":")[1]
    denied_message = (
        f"User: {user_arn} is not authorized to perform: "
        f"mgn:CreateReplicationConfigurationTemplate on resource: "
        f"arn:{partition}:mgn:{ctx.region}:{ctx.account}:replication-configuration-template/* "
        f"because no identity-based policy allows the mgn:CreateReplicationConfigurationTemplate "
        f"action"
    )
    assert last_error["error"].get("Message") == denied_message, (
        f"expected AccessDeniedException message {denied_message!r}, got "
        f"{last_error['error'].get('Message')!r}"
    )

    # Effect-absent via an independent read: even if the client-visible denial had raced
    # with a server-side write, the account's templates must be the same ones.
    ids_after = _template_ids()
    assert ids_after == ids_before, (
        f"expected no new template server-side after the denied attempt, "
        f"had {sorted(ids_before)} before and {sorted(ids_after)} after"
    )

    # Restore: grant exactly the missing permission and demand the identical call now has the
    # privileged identity's outcome -- proving the earlier AccessDenied traced to the policy.
    policy_name = f"{user_name}-allow-create-rct"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "mgn:CreateReplicationConfigurationTemplate",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    restored = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        restored = _outcome(unpriv_mgn)
        if restored == baseline:
            break
        time.sleep(5.0)
    assert restored == baseline, (
        f"expected the identical call to have the privileged outcome {baseline!r} once granted "
        f"the permission, got {restored!r} ({last_error.get('error')!r})"
    )
    assert last_error["error"].get("Message") == quota_message, (
        f"expected the granted identity's quota message {quota_message!r}, got "
        f"{last_error['error'].get('Message')!r}"
    )


def _ensure_initialized(mgn) -> None:
    init_error = None
    try:
        mgn.initialize_service()
    except ClientError as e:
        init_error = e.response["Error"]["Code"]
    # The account-initialized flag has been observed to lag a successful InitializeService
    # (or a successful Create) by a few seconds -- a later read on the same account can still
    # answer UninitializedAccountException. Bounded retry on that one code; anything else raises.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            mgn.describe_replication_configuration_templates(maxResults=1)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "UninitializedAccountException" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"account did not become initialized; InitializeService itself answered "
                    f"{init_error!r}, last describe answered {e.response['Error']['Code']!r}"
                ) from e
            time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
