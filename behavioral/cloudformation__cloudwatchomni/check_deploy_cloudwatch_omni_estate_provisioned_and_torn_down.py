"""deploy-cloudwatch-omni-estate-provisioned-and-torn-down."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-omni-estate-provisioned-and-torn-down"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatchomni"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


# ---- Check-specific: the template, then run(). ----

def _update_stack(cf, stack_id: str, template: dict, drop: tuple[str, ...]) -> None:
    """Update the stack to ``template`` without the ``drop`` resources; UPDATE_COMPLETE or raise."""
    body = {
        "Resources": {k: v for k, v in template["Resources"].items() if k not in drop},
        "Outputs": {
            k: v for k, v in template["Outputs"].items()
            if (v["Value"].get("Ref") or v["Value"]["Fn::GetAtt"][0]) not in drop
        },
    }
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(body),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"removing {drop} ended {status!r}, not UPDATE_COMPLETE"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:cloudwatch-domain",
)
def run(ctx) -> None:
    """A CFN stack provisions a Domain, Space, AccessProfile, AccessGrant, Integration and
    OmniDashboard that read back through cloudwatchomni with the template's values, and each
    type's own delete (children by stack update under live parents, then the Domain) removes it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudwatch-domain.html
    """
    cf = ctx.client("cloudformation")
    cwo = ctx.client("cloudwatchomni")

    prior = paginate(cwo, "list_domains", "items")
    assert prior == [], (
        f"precondition: the account already holds {len(prior)} CloudWatch domain(s), and a "
        "domain is once per account; this check needs an account without one"
    )

    stack_name = ctx.unique_name("sim2real-behav-omnistk-")
    domain_name = ctx.unique_name("sim2real-behav-domain-")
    space_name = ctx.unique_name("sim2real-behav-space-")
    data_role_name = ctx.unique_name("sim2real-behav-datarole-")
    principal_role_name = ctx.unique_name("sim2real-behav-princrole-")
    profile_name = ctx.unique_name("sim2real-behav-profile-")
    grant_name = ctx.unique_name("sim2real-behav-grant-")
    integration_name = ctx.unique_name("sim2real-behav-integ-")
    dashboard_name = ctx.unique_name("sim2real-behav-dash-")
    dashboard_body = json.dumps({"panels": []})

    assume_role_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    template = {
        "Resources": {
            "DataAccessRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": data_role_name,
                    "AssumeRolePolicyDocument": assume_role_doc,
                },
            },
            "PrincipalRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": principal_role_name,
                    "AssumeRolePolicyDocument": assume_role_doc,
                },
            },
            "Domain": {
                "Type": "AWS::CloudWatch::Domain",
                "Properties": {"Name": domain_name, "IdentityProviders": ["IAM"]},
            },
            "Space": {
                "Type": "AWS::CloudWatch::Space",
                "Properties": {
                    "Name": space_name,
                    "DomainId": {"Fn::GetAtt": ["Domain", "DomainId"]},
                    "DataAccessRoleArn": {"Fn::GetAtt": ["DataAccessRole", "Arn"]},
                },
            },
            "Profile": {
                "Type": "AWS::CloudWatch::AccessProfile",
                "Properties": {
                    "SpaceId": {"Fn::GetAtt": ["Space", "SpaceId"]},
                    "Name": profile_name,
                },
            },
            "Grant": {
                "Type": "AWS::CloudWatch::AccessGrant",
                "Properties": {
                    "DomainId": {"Fn::GetAtt": ["Domain", "DomainId"]},
                    "SpaceId": {"Fn::GetAtt": ["Space", "SpaceId"]},
                    "Name": grant_name,
                    "Principal": {
                        "PrincipalType": "IAM_ROLE",
                        "PrincipalId": {"Fn::GetAtt": ["PrincipalRole", "Arn"]},
                    },
                    "Permission": "READ",
                },
            },
            "Integration": {
                "Type": "AWS::CloudWatch::Integration",
                "Properties": {
                    "IntegrationType": "AWS_INTEGRATION",
                    "Name": integration_name,
                    "RoleArn": {"Fn::GetAtt": ["DataAccessRole", "Arn"]},
                },
            },
            "Dashboard": {
                "Type": "AWS::CloudWatch::OmniDashboard",
                "Properties": {
                    "SpaceId": {"Fn::GetAtt": ["Space", "SpaceId"]},
                    "Name": dashboard_name,
                    "Body": dashboard_body,
                },
            },
        },
        "Outputs": {
            "DomainRef": {"Value": {"Ref": "Domain"}},
            "DomainId": {"Value": {"Fn::GetAtt": ["Domain", "DomainId"]}},
            "SpaceRef": {"Value": {"Ref": "Space"}},
            "SpaceId": {"Value": {"Fn::GetAtt": ["Space", "SpaceId"]}},
            "ProfileRef": {"Value": {"Ref": "Profile"}},
            "GrantRef": {"Value": {"Ref": "Grant"}},
            "IntegrationRef": {"Value": {"Ref": "Integration"}},
            "DashboardRef": {"Value": {"Ref": "Dashboard"}},
            "DashboardId": {"Value": {"Fn::GetAtt": ["Dashboard", "DashboardId"]}},
            "ProfileId": {"Value": {"Fn::GetAtt": ["Profile", "ProfileId"]}},
            "GrantId": {"Value": {"Fn::GetAtt": ["Grant", "GrantId"]}},
            "IntegrationId": {"Value": {"Fn::GetAtt": ["Integration", "IntegrationId"]}},
            "DataRoleArn": {"Value": {"Fn::GetAtt": ["DataAccessRole", "Arn"]}},
            "PrincipalRoleArn": {"Value": {"Fn::GetAtt": ["PrincipalRole", "Arn"]}},
        },
    }

    stack_id = create_stack(ctx, cf, stack_name, json.dumps(template),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    domain_id = outputs["DomainId"]
    space_id = outputs["SpaceId"]
    profile_id = outputs["ProfileId"]
    grant_id = outputs["GrantId"]
    integration_arn = outputs["IntegrationRef"]
    dashboard_id = outputs["DashboardId"]
    data_role_arn = outputs["DataRoleArn"]
    principal_role_arn = outputs["PrincipalRoleArn"]

    got_domain = cwo.get_domain(domainId=domain_id)["domain"]
    assert outputs["DomainRef"] == got_domain["domainArn"], (
        f"Ref of the Domain should be its ARN {got_domain['domainArn']!r}, got {outputs['DomainRef']!r}"
    )
    assert got_domain["domainId"] == domain_id, (
        f"GetAtt DomainId should be the service's {got_domain['domainId']!r}, got {domain_id!r}"
    )
    assert got_domain["name"] == domain_name, (
        f"expected domain name {domain_name!r}, got {got_domain['name']!r}"
    )
    assert got_domain["identityProviders"] == ["IAM"], (
        f"expected identityProviders ['IAM'], got {got_domain['identityProviders']!r}"
    )
    assert got_domain["status"] == "ACTIVE", f"expected domain status ACTIVE, got {got_domain['status']!r}"

    got_space = cwo.get_space(spaceId=space_id)["space"]
    assert outputs["SpaceRef"] == got_space["spaceArn"], (
        f"Ref of the Space should be its ARN {got_space['spaceArn']!r}, got {outputs['SpaceRef']!r}"
    )
    assert got_space["spaceId"] == space_id, (
        f"GetAtt SpaceId should be the service's {got_space['spaceId']!r}, got {space_id!r}"
    )
    assert got_space["name"] == space_name, f"expected space name {space_name!r}, got {got_space['name']!r}"
    assert got_space["dataAccessRoleArn"] == data_role_arn, (
        f"expected dataAccessRoleArn {data_role_arn!r}, got {got_space['dataAccessRoleArn']!r}"
    )
    assert got_space["domainArn"] == got_domain["domainArn"], (
        f"expected space's domainArn {got_domain['domainArn']!r}, got {got_space['domainArn']!r}"
    )

    got_profile = cwo.get_access_profile(spaceId=space_id, profileId=profile_id)["accessProfile"]
    assert outputs["ProfileRef"] == f"{got_profile['spaceId']}|{got_profile['profileId']}", (
        f"Ref of the AccessProfile should be SpaceId|ProfileId, got {outputs['ProfileRef']!r}"
    )
    assert got_profile["name"] == profile_name, (
        f"expected profile name {profile_name!r}, got {got_profile['name']!r}"
    )
    assert got_profile["spaceId"] == space_id, (
        f"expected profile's spaceId {space_id!r}, got {got_profile['spaceId']!r}"
    )

    got_grant = cwo.get_access_grant(grantId=grant_id)["accessGrant"]
    assert outputs["GrantRef"] == got_grant["grantArn"], (
        f"Ref of the AccessGrant should be its ARN {got_grant['grantArn']!r}, got {outputs['GrantRef']!r}"
    )
    assert got_grant["name"] == grant_name, f"expected grant name {grant_name!r}, got {got_grant['name']!r}"
    assert (got_grant["domainId"], got_grant["spaceId"]) == (domain_id, space_id), (
        f"expected the grant on domain {domain_id!r} and space {space_id!r}, "
        f"got {(got_grant['domainId'], got_grant['spaceId'])!r}"
    )
    assert got_grant["permission"] == "READ", (
        f"expected grant permission READ, got {got_grant['permission']!r}"
    )
    assert got_grant["principal"] == {
        "principalType": "IAM_ROLE", "principalId": principal_role_arn, "principalAttributes": [],
    }, f"expected grant principal IAM_ROLE {principal_role_arn!r}, got {got_grant['principal']!r}"

    got_integration = cwo.get_integration(
        identifier={"integrationArn": integration_arn})["integration"]
    assert outputs["IntegrationRef"] == got_integration["integrationArn"], (
        f"Ref of the Integration should be its ARN {got_integration['integrationArn']!r}, "
        f"got {outputs['IntegrationRef']!r}"
    )
    assert got_integration["integrationId"] == outputs["IntegrationId"], (
        f"GetAtt IntegrationId should be the service's {got_integration['integrationId']!r}, "
        f"got {outputs['IntegrationId']!r}"
    )
    assert got_integration["name"] == integration_name, (
        f"expected integration name {integration_name!r}, got {got_integration['name']!r}"
    )
    assert got_integration["integrationType"] == "AWS_INTEGRATION", (
        f"expected integrationType AWS_INTEGRATION, got {got_integration['integrationType']!r}"
    )
    assert got_integration["roleArn"] == data_role_arn, (
        f"expected integration roleArn {data_role_arn!r}, got {got_integration['roleArn']!r}"
    )

    got_dashboard = cwo.get_omni_dashboard(
        spaceId=space_id, dashboardId=dashboard_id)["omniDashboard"]
    assert outputs["DashboardRef"] == f"{space_id}|{got_dashboard['dashboardId']}", (
        f"Ref of the OmniDashboard should be SpaceId|DashboardId, got {outputs['DashboardRef']!r}"
    )
    assert got_dashboard["name"] == dashboard_name, (
        f"expected dashboard name {dashboard_name!r}, got {got_dashboard['name']!r}"
    )
    assert got_dashboard["body"] == dashboard_body, (
        f"expected dashboard body {dashboard_body!r}, got {got_dashboard['body']!r}"
    )

    # ---- The space's children leave first, each read absent under its live parent. ----
    _update_stack(cf, stack_id, template, ("Dashboard", "Profile", "Grant"))
    dashboards = {d["dashboardId"] for d in paginate(cwo, "list_omni_dashboards", "items", spaceId=space_id)}
    assert dashboard_id not in dashboards, "the removed OmniDashboard is still listed in its space"
    profiles = {p["profileId"] for p in paginate(cwo, "list_access_profiles", "items", spaceId=space_id)}
    assert profile_id not in profiles, "the removed AccessProfile is still listed in its space"
    grants = {g["grantId"] for g in paginate(cwo, "list_access_grants", "items", domainId=domain_id)}
    assert grant_id not in grants, "the removed AccessGrant is still listed in its domain"

    # ---- Then the Space and the Integration, while the Domain remains. ----
    _update_stack(cf, stack_id, template, ("Dashboard", "Profile", "Grant", "Space", "Integration"))
    spaces = {sp["spaceId"] for sp in paginate(cwo, "list_spaces", "items", domainId=domain_id)}
    assert space_id not in spaces, "the removed Space is still listed in its domain"
    integrations = {
        i["integrationArn"]
        for i in paginate(cwo, "list_integrations", "items", integrationType="AWS_INTEGRATION", name=integration_name)
    }
    assert integration_arn not in integrations, "the removed Integration is still listed by its name"

    # ---- Last, the stack delete removes the Domain. ----
    delete_stack(cf, stack_id)
    domains = {d["domainId"] for d in paginate(cwo, "list_domains", "items")}
    assert domain_id not in domains, "the deleted stack's Domain is still listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
