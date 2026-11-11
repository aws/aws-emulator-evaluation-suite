"""deploy-codeartifact-domain-repo-packagegroup-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codeartifact-domain-repo-packagegroup-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "codeartifact"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

def _tags(value):
    return [{"Key": "sim2real-ca", "Value": value}]


def _own_tags(ca, arn):
    """The resource's tags as sorted (key, value), without CloudFormation's aws: system tags."""
    tags_ = ca.list_tags_for_resource(resourceArn=arn)["tags"]
    return sorted((t["key"], t["value"]) for t in tags_ if not t["key"].startswith("aws:"))


def _template(domain_name, repo_name=None, pattern=None, repo_description=""):
    """A Domain, and optionally a Repository and a PackageGroup that depend on it."""
    resources = {
        "Domain": {"Type": "AWS::CodeArtifact::Domain", "Properties": {
            "DomainName": domain_name, "Tags": _tags(domain_name),
        }},
    }
    outputs = {
        "DomainRef": {"Value": {"Ref": "Domain"}},
        "DomainGetAttName": {"Value": {"Fn::GetAtt": "Domain.Name"}},
        "DomainGetAttOwner": {"Value": {"Fn::GetAtt": "Domain.Owner"}},
        "DomainGetAttEncryptionKey": {"Value": {"Fn::GetAtt": "Domain.EncryptionKey"}},
    }
    if repo_name is not None:
        resources["Repository"] = {"Type": "AWS::CodeArtifact::Repository", "DependsOn": "Domain",
                                   "Properties": {
                                       "DomainName": domain_name,
                                       "RepositoryName": repo_name,
                                       "Description": repo_description,
                                       "Tags": _tags(domain_name),
                                   }}
        outputs["RepoRef"] = {"Value": {"Ref": "Repository"}}
        outputs["RepoGetAttName"] = {"Value": {"Fn::GetAtt": "Repository.Name"}}
        outputs["RepoGetAttDomainOwner"] = {"Value": {"Fn::GetAtt": "Repository.DomainOwner"}}
    if pattern is not None:
        resources["PackageGroup"] = {"Type": "AWS::CodeArtifact::PackageGroup",
                                     "DependsOn": "Domain",
                                     "Properties": {"DomainName": domain_name, "Pattern": pattern,
                                                    "Tags": _tags(domain_name)}}
        outputs["PackageGroupRef"] = {"Value": {"Ref": "PackageGroup"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


_DOMAIN_GONE = "Domain not found. Domain '{domain}' owned by account '{account}' does not exist."
_REPO_GONE = (
    "Repository not found. Repository '{repo}' in domain '{domain}' owned by account "
    "'{account}' does not exist."
)
_PACKAGE_GROUP_GONE = (
    "Package Group not found not found. Package Group '{pattern}' in domain {domain} owned by "
    "account {account} does not exist"
)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Domain, Repository and PackageGroup are real CodeArtifact resources.

    Ref is each resource's ARN and every GetAtt, templated property and tag matches the CodeArtifact
    read; dropping the children leaves the same domain in place, and deleting the stack removes it.
    """
    cf = ctx.client("cloudformation")
    ca = ctx.client("codeartifact")
    stack_name = ctx.unique_name("sim2real-cfnca-rt-")
    domain_name = ctx.unique_name("sim2real-cfnca-rt-dom-")
    repo_name = ctx.unique_name("sim2real-cfnca-rt-repo-")
    pattern = "/pypi/*"
    description = "sim2real round-trip repository"

    stack_id = create_stack(
        ctx, cf, stack_name, _template(domain_name, repo_name, pattern, description)
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Independent reads, by the names the check declared — never by the Ref being checked.
    domain = ca.describe_domain(domain=domain_name)["domain"]
    repo = ca.describe_repository(domain=domain_name, repository=repo_name)["repository"]
    pkg_group = ca.describe_package_group(domain=domain_name, packageGroup=pattern)["packageGroup"]

    # Ref == primary identifier (Arn) for every type.
    assert out["DomainRef"] == domain["arn"], f"Domain Ref {out['DomainRef']!r} != {domain['arn']!r}"
    assert out["RepoRef"] == repo["arn"], f"Repository Ref {out['RepoRef']!r} != {repo['arn']!r}"
    assert out["PackageGroupRef"] == pkg_group["arn"], (
        f"PackageGroup Ref {out['PackageGroupRef']!r} != {pkg_group['arn']!r}"
    )

    # Read-only GetAtt values == the service's own read.
    assert out["DomainGetAttName"] == domain["name"] == domain_name, (
        f"Domain GetAtt Name {out['DomainGetAttName']!r}, describe name {domain['name']!r}"
    )
    assert out["DomainGetAttOwner"] == domain["owner"] == ctx.account, (
        f"Domain GetAtt Owner {out['DomainGetAttOwner']!r}, describe owner {domain['owner']!r}"
    )
    assert out["DomainGetAttEncryptionKey"] == domain["encryptionKey"], (
        f"Domain GetAtt EncryptionKey {out['DomainGetAttEncryptionKey']!r} != "
        f"describe encryptionKey {domain['encryptionKey']!r}"
    )
    assert out["RepoGetAttName"] == repo["name"] == repo_name, (
        f"Repository GetAtt Name {out['RepoGetAttName']!r}, describe name {repo['name']!r}"
    )
    assert out["RepoGetAttDomainOwner"] == repo["domainOwner"] == ctx.account, (
        f"Repository GetAtt DomainOwner {out['RepoGetAttDomainOwner']!r}, "
        f"describe domainOwner {repo['domainOwner']!r}"
    )

    # Every templated property reads back through CodeArtifact.
    assert domain["status"] == "Active", f"domain status {domain['status']!r}, expected Active"
    assert repo["domainName"] == domain_name, f"repository domainName {repo['domainName']!r}"
    assert repo["description"] == description, f"repository description {repo['description']!r}"
    assert pkg_group["domainName"] == domain_name, f"package group domainName {pkg_group['domainName']!r}"
    assert pkg_group["pattern"] == pattern, f"package group pattern {pkg_group['pattern']!r}"

    # The templated tag and the propagated stack tag on each of the three.
    want_tags = [("sim2real", stack_name), ("sim2real-ca", domain_name)]
    for arn in (domain["arn"], repo["arn"], pkg_group["arn"]):
        assert _own_tags(ca, arn) == want_tags, f"{arn} tags {_own_tags(ca, arn)!r}"

    # A server-minted identity, captured before the update, proves the domain is not recreated.
    domain_created_at = domain["createdTime"]

    # Drop Repository and PackageGroup; the domain survives in place.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(domain_name))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"update ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    refused = (
        "ResourceNotFoundException",
        _REPO_GONE.format(repo=repo_name, domain=domain_name, account=ctx.account),
    )
    expect_error(lambda: ca.describe_repository(domain=domain_name, repository=repo_name), *refused)
    refused = (
        "ResourceNotFoundException",
        _PACKAGE_GROUP_GONE.format(pattern=pattern, domain=domain_name, account=ctx.account),
    )
    expect_error(
        lambda: ca.describe_package_group(domain=domain_name, packageGroup=pattern),
        *refused,
    )
    after_update = ca.describe_domain(domain=domain_name)["domain"]
    assert after_update["createdTime"] == domain_created_at, (
        f"domain createdTime changed from {domain_created_at!r} to {after_update['createdTime']!r} "
        "— the update recreated it instead of leaving it in place"
    )
    assert after_update["repositoryCount"] == 0, (
        f"domain repositoryCount {after_update['repositoryCount']!r} after dropping the repository"
    )

    delete_stack(cf, stack_id)
    refused = (
        "ResourceNotFoundException",
        _DOMAIN_GONE.format(domain=domain_name, account=ctx.account),
    )
    expect_error(lambda: ca.describe_domain(domain=domain_name), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
