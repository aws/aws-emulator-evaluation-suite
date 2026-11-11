"""deploy-emrcontainers-securityconfiguration-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-emrcontainers-securityconfiguration-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "emr-containers"]

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

_LF_TAG = "sim2real-lf-tag"
_NAMESPACE_INFO = {"ClusterId": "sim2real-cluster-id", "Namespace": "sim2real-namespace"}


def _secret_arn(name):
    return {"Fn::Sub": f"arn:${{AWS::Partition}}:secretsmanager:${{AWS::Region}}:"
                       f"${{AWS::AccountId}}:secret:{name}"}


def _template(name, public_secret, private_secret):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "QueryEngineRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "SecurityConfiguration": {"Type": "AWS::EMRContainers::SecurityConfiguration",
                                      "Properties": {
                "Name": name,
                "SecurityConfigurationData": {
                    "EncryptionConfiguration": {"InTransitEncryptionConfiguration": {
                        "TLSCertificateConfiguration": {
                            "CertificateProviderType": "PEM",
                            "PublicKeySecretArn": _secret_arn(public_secret),
                            "PrivateKeySecretArn": _secret_arn(private_secret),
                        }}},
                    "AuthorizationConfiguration": {"LakeFormationConfiguration": {
                        "AuthorizedSessionTagValue": _LF_TAG,
                        "QueryEngineRoleArn": {"Fn::GetAtt": ["QueryEngineRole", "Arn"]},
                        "SecureNamespaceInfo": _NAMESPACE_INFO,
                    }},
                },
                "Tags": [{"Key": "sim2real-sc", "Value": name}],
            }},
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["QueryEngineRole", "Arn"]}},
            "SecurityConfigurationArn": {"Value": {"Ref": "SecurityConfiguration"}},
            "SecurityConfigurationId": {"Value": {"Fn::GetAtt": ["SecurityConfiguration", "Id"]}},
        },
    })


def _config_not_found(config_id):
    return ("ResourceNotFoundException", f"Security Configuration {config_id} doesn't exist.")


def _delete_config(emrc, config_id):
    """Delete the configuration directly; only its exact not-found answer means already gone."""
    try:
        emrc.delete_security_configuration(id=config_id)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        if got != ("ValidationException", "Security configuration not found"):
            raise


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EMR on EKS security configuration reads back its TLS and Lake Formation data.

    Deleting the stack, then the configuration's own delete (already gone is accepted), leave it
    absent from EMR Containers.
    """
    cf = ctx.client("cloudformation")
    emrc = ctx.client("emr-containers")
    stack = ctx.unique_name("sim2real-behav-cfn-sc-")
    name = ctx.unique_name("sim2realbehavsc")
    public_secret = ctx.unique_name("sim2real-pub-")
    private_secret = ctx.unique_name("sim2real-priv-")

    stack_id = create_stack(ctx, cf, stack, _template(name, public_secret, private_secret),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    config_id = out["SecurityConfigurationId"]
    ctx.on_cleanup(lambda: _delete_config(emrc, config_id))
    secret_prefix = f"arn:{stack_id.split(':')[1]}:secretsmanager:{ctx.region}:{ctx.account}:secret:"

    # Ref and GetAtt Id against an independent ListSecurityConfigurations by the declared name.
    listed = [(c["arn"], c["id"]) for c in paginate(
        emrc, "list_security_configurations", "securityConfigurations") if c["name"] == name]
    assert listed == [(out["SecurityConfigurationArn"], config_id)], f"listed {listed!r}"
    sc = emrc.describe_security_configuration(id=config_id)["securityConfiguration"]
    auth = sc["securityConfigurationData"]["authorizationConfiguration"]
    tls = auth["encryptionConfiguration"]["inTransitEncryptionConfiguration"][
        "tlsCertificateConfiguration"]
    lf = auth["lakeFormationConfiguration"]
    got = (sc["name"], tls, lf,
           {k: v for k, v in sc.get("tags", {}).items() if not k.startswith("aws:")})
    want = (name,
            {"certificateProviderType": "PEM",
             "publicCertificateSecretArn": secret_prefix + public_secret,
             "privateCertificateSecretArn": secret_prefix + private_secret},
            {"authorizedSessionTagValue": _LF_TAG, "queryEngineRoleArn": out["RoleArn"],
             "secureNamespaceInfo": {"clusterId": _NAMESPACE_INFO["ClusterId"],
                                     "namespace": _NAMESPACE_INFO["Namespace"]}},
            {"sim2real": stack, "sim2real-sc": name})
    assert got == want, f"DescribeSecurityConfiguration {got!r}, expected {want!r}"

    delete_stack(cf, stack_id)
    _delete_config(emrc, config_id)
    config_gone = _config_not_found(config_id)
    expect_error(lambda: emrc.describe_security_configuration(id=config_id), *config_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
