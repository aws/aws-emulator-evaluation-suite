"""role-scoped-to-parameter-path-prefix-denies-outside-subtree."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-scoped-to-parameter-path-prefix-denies-outside-subtree"
GROUP = "error-semantics"
SERVICES = ["ssm"]


def _client_error(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _assume_role_with_retry(sts, role_arn, session_name, attempts=10, delay_s=3.0):
    """IAM role-trust propagation can lag a few seconds after CreateRole; retry AssumeRole
    itself (not any check assertion) until the freshly created role is assumable."""
    last_exc = None
    for _ in range(attempts):
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _access_denied_retry(fn, attempts=10, delay_s=3.0):
    """A freshly attached identity-based policy can lag AssumeRole's own propagation; retry an
    unexpected AccessDeniedException on the call the check expects to SUCCEED, never on the one
    it expects to fail."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "plane:control",
)
def run(ctx) -> None:
    """A role allowed ssm:GetParameter* on .../app/* reads inside it and gets the exact IAM denial
    outside it; GetParameters and GetParametersByPath over a mixed subtree fail closed, and
    GetParametersByPath is authorized on its literal Path argument.
    """

    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    base = "/" + ctx.unique_name("sim2real-behav-ssmscope")
    app_prefix = f"{base}/app"
    other_prefix = f"{base}/other"
    param_app = f"{app_prefix}/x"
    param_other = f"{other_prefix}/x"
    # One level deeper than app_prefix, so a GetParametersByPath here checks a resource of
    # "parameter{app_prefix}/nested" against the policy's "parameter{app_prefix}/*" -- a
    # literal match -- unlike Path=app_prefix itself (see below).
    nested_prefix = f"{app_prefix}/nested"
    param_nested = f"{nested_prefix}/y"

    for name, value in (
        (param_app, "app-value"),
        (param_other, "other-value"),
        (param_nested, "nested-value"),
    ):
        ssm.put_parameter(
            Name=name,
            Value=value,
            Type="String",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda name=name: ssm.delete_parameter(Name=name))

    allowed_resource = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{app_prefix}/*"
    role_name = ctx.unique_name("sim2real-behav-ssmscope-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-perms"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ssm:GetParameter*",
                        "Resource": allowed_resource,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    session_name = ctx.unique_name("sim2real-session-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    restricted = ctx.client(
        "ssm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    assumed_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name}"

    # --- in scope: the role reads the parameter under the allowed subtree ----
    in_scope = _access_denied_retry(
        lambda: restricted.get_parameter(Name=param_app)
    )["Parameter"]
    assert in_scope["Value"] == "app-value", (
        f"an in-scope GetParameter must return its value, got {in_scope!r}"
    )

    # --- out of scope: one hop outside the allowed subtree is denied, exactly -
    other_arn = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{param_other}"
    code, message = _client_error(lambda: restricted.get_parameter(Name=param_other))
    assert code == "AccessDeniedException", (
        f"GetParameter outside the allowed subtree must be AccessDeniedException, got {code!r}"
    )
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: ssm:GetParameter on resource: "
        f"{other_arn} because no identity-based policy allows the ssm:GetParameter action"
    ), f"unexpected message {message!r}"

    # --- GetParameters over a mixed subtree: fails closed, not partially ------
    code, message = _client_error(
        lambda: restricted.get_parameters(Names=[param_app, param_other])
    )
    assert code == "AccessDeniedException", (
        "GetParameters over names split across the allowed and denied subtrees must fail "
        f"closed with AccessDeniedException rather than returning the authorized half; got "
        f"{code!r}"
    )
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: ssm:GetParameters on resource: "
        f"{other_arn} because no identity-based policy allows the ssm:GetParameters action"
    ), f"unexpected message {message!r}"

    # --- GetParametersByPath over the mixed parent: the Path itself is checked
    # against the resource pattern, not filtered after the read -----------------
    code, message = _client_error(
        lambda: restricted.get_parameters_by_path(Path=base, Recursive=True)
    )
    assert code == "AccessDeniedException", (
        "GetParametersByPath whose Path spans both the allowed and denied subtrees must be "
        f"refused in full rather than silently filtered; got {code!r}"
    )
    base_resource = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{base}"
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: ssm:GetParametersByPath on "
        f"resource: {base_resource} because no identity-based policy allows the "
        "ssm:GetParametersByPath action"
    ), f"unexpected message {message!r}"

    # --- Path=app_prefix is the resource "parameter{app_prefix}" with no trailing segment, which
    # "parameter{app_prefix}/*" does not match, though every parameter under it is readable ---
    app_prefix_resource = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter{app_prefix}"
    code, message = _client_error(
        lambda: restricted.get_parameters_by_path(Path=app_prefix, Recursive=True)
    )
    assert code == "AccessDeniedException", (
        "GetParametersByPath(Path=app_prefix) must be denied: the request's own resource is "
        f"the literal path with no trailing segment, which 'parameter.../app/*' does not "
        f"match; got {code!r}"
    )
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: ssm:GetParametersByPath on "
        f"resource: {app_prefix_resource} because no identity-based policy allows the "
        "ssm:GetParametersByPath action"
    ), f"unexpected message {message!r}"

    # --- positive control: GetParametersByPath over a path ONE LEVEL DEEPER
    # than app_prefix computes a resource that the wildcard DOES match, and
    # succeeds on the SAME restricted role -------------------------------------
    scoped = _access_denied_retry(
        lambda: restricted.get_parameters_by_path(Path=nested_prefix, Recursive=True)
    )["Parameters"]
    assert [p["Name"] for p in scoped] == [param_nested], (
        f"a Path nested inside the allowed resource pattern must succeed and return exactly "
        f"{param_nested!r}, got {[p['Name'] for p in scoped]!r}"
    )
    assert scoped[0]["Value"] == "nested-value", scoped

    # --- positive control: the admin's own identical-shape batch reads succeed,
    # proving the two denials above are about authorization, not a malformed
    # request or a broken client/endpoint --------------------------------------
    admin_batch = ssm.get_parameters(Names=[param_app, param_other])
    assert admin_batch["InvalidParameters"] == [], admin_batch
    assert {p["Name"]: p["Value"] for p in admin_batch["Parameters"]} == {
        param_app: "app-value",
        param_other: "other-value",
    }, admin_batch
    admin_path = ssm.get_parameters_by_path(Path=base, Recursive=True)["Parameters"]
    assert {p["Name"] for p in admin_path} == {param_app, param_other, param_nested}, admin_path


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
