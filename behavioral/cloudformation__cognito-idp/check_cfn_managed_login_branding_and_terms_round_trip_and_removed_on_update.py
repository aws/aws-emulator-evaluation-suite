"""cfn-managed-login-branding-and-terms-round-trip-and-removed-on-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-managed-login-branding-and-terms-round-trip-and-removed-on-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

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

def _template(*, with_branding_and_terms: bool, pool_name: str, client_name: str, domain: str,
              tos_link: str) -> str:
    resources = {
        "Pool": {"Type": "AWS::Cognito::UserPool", "Properties": {"UserPoolName": pool_name}},
        "Client": {
            "Type": "AWS::Cognito::UserPoolClient",
            "Properties": {"UserPoolId": {"Ref": "Pool"}, "ClientName": client_name},
        },
        # ManagedLoginBranding needs a domain; its hosted login page serves a pool with no users
        # and no callback URLs, so nothing is reachable through it.
        "Domain": {
            "Type": "AWS::Cognito::UserPoolDomain",
            "Properties": {"UserPoolId": {"Ref": "Pool"}, "Domain": domain, "ManagedLoginVersion": 2},
        },
    }
    outputs = {"PoolRef": {"Value": {"Ref": "Pool"}}, "ClientRef": {"Value": {"Ref": "Client"}}}
    if with_branding_and_terms:
        resources["Branding"] = {
            "Type": "AWS::Cognito::ManagedLoginBranding",
            "DependsOn": "Domain",
            "Properties": {
                "UserPoolId": {"Ref": "Pool"},
                "ClientId": {"Ref": "Client"},
                "UseCognitoProvidedValues": True,
            },
        }
        resources["Terms"] = {
            "Type": "AWS::Cognito::Terms",
            "Properties": {
                "UserPoolId": {"Ref": "Pool"},
                "ClientId": {"Ref": "Client"},
                "TermsName": "terms-of-use",
                "TermsSource": "LINK",
                "Enforcement": "NONE",
                "Links": {"cognito:default": tos_link},
            },
        }
        outputs["BrandingRef"] = {"Value": {"Ref": "Branding"}}
        outputs["TermsRef"] = {"Value": {"Ref": "Terms"}}
        outputs["BrandingId"] = {"Value": {"Fn::GetAtt": ["Branding", "ManagedLoginBrandingId"]}}
        outputs["TermsId"] = {"Value": {"Fn::GetAtt": ["Terms", "TermsId"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _terms(cognito, pool_id):
    """Every Terms entry of the pool, across every NextToken page (ListTerms has no paginator)."""
    items, token = [], None
    while True:
        page = cognito.list_terms(UserPoolId=pool_id, **({"NextToken": token} if token else {}))
        items += page["Terms"]
        token = page.get("NextToken")
        if not token:
            return items


def _identities(cognito, pool_id, client_id, domain):
    """Server-minted identities of the pool, client and domain the update must leave untouched."""
    domain_desc = cognito.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    return (
        cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]["CreationDate"],
        cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
            "UserPoolClient"]["CreationDate"],
        domain_desc["UserPoolId"], domain_desc["CloudFrontDistribution"], domain_desc["Version"],
        domain_desc["ManagedLoginVersion"],
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation ManagedLoginBranding and Terms on a pool client read back, then an update drops them.

    Refs and id GetAtts match the by-client branding and the ListTerms entry with every templated
    value; after the update each is NotFound while the same pool, client and domain remain.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-cogmlbtpool-")
    client_name = ctx.unique_name("sim2real-behav-cogmlbtclient-")
    domain = ctx.unique_name("sim2real-behav-cogmlbtdom-").lower()[:63].rstrip("-")
    tos_link = "https://example.com/tos"
    names = {"pool_name": pool_name, "client_name": client_name, "domain": domain,
             "tos_link": tos_link}

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cogmlbtstack-"),
                            _template(with_branding_and_terms=True, **names))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    pool_id, client_id = out["PoolRef"], out["ClientRef"]
    clients = [c["ClientId"] for c in paginate(cognito, "list_user_pool_clients", "UserPoolClients",
                                               UserPoolId=pool_id) if c["ClientName"] == client_name]
    assert clients == [client_id], f"ListUserPoolClients named {client_name!r}: {clients!r}"

    branding = cognito.describe_managed_login_branding_by_client(
        UserPoolId=pool_id, ClientId=client_id)["ManagedLoginBranding"]
    branding_id = branding["ManagedLoginBrandingId"]
    assert (out["BrandingRef"], out["BrandingId"]) == (f"{pool_id}|{branding_id}", branding_id), (
        f"ManagedLoginBranding Ref {out['BrandingRef']!r}, GetAtt {out['BrandingId']!r}; "
        f"by-client id {branding_id!r}"
    )
    assert (branding["UserPoolId"], branding["UseCognitoProvidedValues"]) == (pool_id, True), (
        f"ManagedLoginBranding {branding!r}"
    )

    listed = [t for t in _terms(cognito, pool_id) if t["TermsName"] == "terms-of-use"]
    assert len(listed) == 1, f"ListTerms named terms-of-use: {listed!r}"
    terms_id = listed[0]["TermsId"]
    assert (out["TermsRef"], out["TermsId"]) == (f"{pool_id}|{terms_id}", terms_id), (
        f"Terms Ref {out['TermsRef']!r}, GetAtt {out['TermsId']!r}; listed id {terms_id!r}"
    )
    terms = cognito.describe_terms(UserPoolId=pool_id, TermsId=terms_id)["Terms"]
    got = {k: terms.get(k) for k in ("ClientId", "TermsName", "TermsSource", "Enforcement", "Links")}
    want = {"ClientId": client_id, "TermsName": "terms-of-use", "TermsSource": "LINK",
            "Enforcement": "NONE", "Links": {"cognito:default": tos_link}}
    assert got == want, f"DescribeTerms {got!r}, expected {want!r}"

    before = _identities(cognito, pool_id, client_id, domain)
    assert before[2] == pool_id and before[5] == 2, f"domain before the update {before!r}"
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(with_branding_and_terms=False, **names))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"Branding/Terms-dropping update ended {status!r}"
    managed_login_branding_gone = (
        "ResourceNotFoundException",
        "ManagedLoginBranding does not exist.",
    )
    expect_error(lambda: cognito.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id),
        *managed_login_branding_gone)
    terms_gone = ("ResourceNotFoundException", "Terms does not exist.")
    expect_error(lambda: cognito.describe_terms(UserPoolId=pool_id, TermsId=terms_id), *terms_gone)
    after = _identities(cognito, pool_id, client_id, domain)
    assert after == before, f"pool, client and domain changed across the update: {before!r} -> {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
