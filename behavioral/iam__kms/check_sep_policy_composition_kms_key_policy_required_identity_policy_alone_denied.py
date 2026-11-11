"""sep-policy-composition-kms-key-policy-required-identity-policy-alone-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-policy-composition-kms-key-policy-required-identity-policy-alone-denied"
GROUP = "auth_enforcement"
SERVICES = ["iam", "kms"]


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _outcome(fn):
    """'OK' when the real signed call succeeds, else its exact AWS error code."""
    code = _error_code(fn)
    return "OK" if code == "UNEXPECTED_SUCCESS" else code


def _client_as(ctx, key_id, secret, service="iam"):
    """A client signing AS the minted principal, on this target's endpoint, region and TLS."""
    return ctx.client(service, creds={
        "aws_access_key_id": key_id,
        "aws_secret_access_key": secret,
    })


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _settle(probe, want, *, description, streak=3, timeout_s=150, interval_s=2):
    """Poll until probe() returns `want` on `streak` consecutive calls; returns all observations.

    IAM is eventually consistent, so a streak keeps one lagging replica from passing as settled.
    """
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; "
                f"last observations {seen[-12:]!r}"
            )
        time.sleep(interval_s)


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _decisions(iam, source_arn, actions, resource_arns, **kw):
    results = iam.simulate_principal_policy(
        PolicySourceArn=source_arn, ActionNames=actions, ResourceArns=resource_arns, **kw
    )["EvaluationResults"]
    return {r["EvalActionName"]: r for r in results}


def _sim_settle(iam, source_arn, actions, resource_arns, want, *, description, **kw):
    """Poll the simulator until every action's EvalDecision equals `want[action]`."""
    last = {}

    def probe():
        nonlocal last
        last = _decisions(iam, source_arn, actions, resource_arns, **kw)
        return {a: last[a]["EvalDecision"] for a in actions}

    _settle(probe, want, description=description, streak=1)
    return last


def _purge_user(iam, user):
    """Undo everything a check may have hung on a user, then delete it."""
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
                 for p in iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
        lambda: [iam.remove_user_from_group(UserName=user, GroupName=g["GroupName"])
                 for g in iam.list_groups_for_user(UserName=user)["Groups"]],
        lambda: iam.delete_user_permissions_boundary(UserName=user),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)


def _mint(ctx, iam, prefix, policy=None):
    name = ctx.unique_name(prefix)
    arn = iam.create_user(UserName=name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, name))
    if policy is not None:
        iam.put_user_policy(UserName=name, PolicyName="identity", PolicyDocument=policy)
    key = iam.create_access_key(UserName=name)["AccessKey"]
    return name, arn, key


def _admin_principal(sts):
    """The harness principal as a key-policy principal (an assumed-role session maps to its role)."""
    ident = sts.get_caller_identity()
    arn, account = ident["Arn"], ident["Account"]
    if ":assumed-role/" in arn:
        role = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        partition = arn.split(":", 2)[1]
        arn = f"arn:{partition}:iam::{account}:role/{role}"
    return arn, account


def _types(result):
    return sorted({m.get("SourcePolicyType") for m in result.get("MatchedStatements", [])})


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """KMS requires the key policy to permit a principal: a user named only in the key policy can
    Encrypt, a user with only an identity-policy Allow gets AccessDeniedException until the key
    policy delegates to the account, and is refused again once the delegation is withdrawn.
    """
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    admin_arn, account = _admin_principal(sts)

    res, res_arn, res_key = _mint(ctx, iam, "sim2real-sep-kms-kp-")
    # The identity policy names the key by ARN, so it is created after the key; the user exists
    # first so the key policy can name the OTHER user now.
    ident_name = ctx.unique_name("sim2real-sep-kms-id-")
    ident_arn = iam.create_user(UserName=ident_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, ident_name))

    def key_policy(key_resource, delegate):
        stmts = [
            {"Sid": "HarnessAdmin", "Effect": "Allow", "Principal": {"AWS": admin_arn},
             "Action": "kms:*", "Resource": key_resource},
            {"Sid": "KeyPolicyOnlyUser", "Effect": "Allow", "Principal": {"AWS": res_arn},
             "Action": "kms:Encrypt", "Resource": key_resource},
        ]
        if delegate:
            stmts.append({"Sid": "DelegateToAccount", "Effect": "Allow",
                          "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                          "Action": "kms:Encrypt", "Resource": key_resource})
        return _policy(*stmts)

    # A just-created user can be refused in a key policy until it propagates.
    created = {}

    def _create():
        created["meta"] = kms.create_key(
            Description="sim2real sep-policy-composition key-policy check",
            Policy=key_policy("*", delegate=False),
            Tags=[{"TagKey": "sim2real", "TagValue": "sep-policy-composition"}],
        )["KeyMetadata"]

    _settle(lambda: _outcome(_create), "OK", description="CreateKey naming the new user", streak=1)
    key_id, key_arn = created["meta"]["KeyId"], created["meta"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    iam.put_user_policy(UserName=ident_name, PolicyName="identity", PolicyDocument=_policy(
        {"Effect": "Allow", "Action": "kms:Encrypt", "Resource": key_arn}))
    ident_key = iam.create_access_key(UserName=ident_name)["AccessKey"]

    # --- Key-policy-only half: simulator and enforcement must agree.
    sim_kp = _decisions(iam, res_arn, ["kms:Encrypt"], [key_arn],
                        ResourcePolicy=key_policy(key_arn, delegate=False))["kms:Encrypt"]
    assert (sim_kp["EvalDecision"], _types(sim_kp)) == ("allowed", ["Resource Policy"]), (
        f"a user named only in the key policy must be allowed by the Resource Policy; got {sim_kp!r}"
    )
    plaintext = uuid.uuid4().bytes
    as_res = _client_as(ctx, res_key["AccessKeyId"], res_key["SecretAccessKey"], service="kms")
    box = {}

    def enc(client):
        box["ct"] = client.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]

    _settle(lambda: _outcome(lambda: enc(as_res)), "OK",
            description="kms:Encrypt by the key-policy-only user", streak=1)
    back = kms.decrypt(CiphertextBlob=box["ct"])
    assert back["Plaintext"] == plaintext and back["KeyId"] == key_arn, (
        f"the ciphertext must decrypt to the exact plaintext under this key; got KeyId {back['KeyId']!r}"
    )

    # --- Identity-policy-only half: refused by KMS regardless of the IAM Allow.
    as_ident = _client_as(ctx, ident_key["AccessKeyId"], ident_key["SecretAccessKey"], service="kms")
    _settle(lambda: _outcome(lambda: as_ident.list_aliases(Limit=1)), "AccessDeniedException",
            description="minted identity-only key is live (an ungranted kms call is refused, not "
                        "InvalidClientTokenId)", streak=1)
    box.clear()
    refusal = (
        "AccessDeniedException",
        f"User: {ident_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        f"because no resource-based policy allows the kms:Encrypt action",
    )
    denied = _error(lambda: enc(as_ident))
    assert denied == refusal, (
        "an identity policy alone cannot grant a KMS key whose policy neither names the user nor "
        f"delegates to the account; expected exactly {refusal!r}, got {denied!r}"
    )
    assert "ct" not in box, "a refused Encrypt must produce no ciphertext"
    # Not asserted: the simulator applies the same-account union rule here and reports `allowed`.
    sim_id = _decisions(iam, ident_arn, ["kms:Encrypt"], [key_arn],
                        ResourcePolicy=key_policy(key_arn, delegate=False))["kms:Encrypt"]
    print(f"[record] simulator verdict for the identity-only leg (not asserted): "
          f"{sim_id['EvalDecision']!r} via {_types(sim_id)!r}; enforcement: {denied[0]!r}")

    # --- Add ONLY the missing delegation: the same identity policy becomes effective.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=key_policy("*", delegate=True))
    _settle(lambda: _outcome(lambda: enc(as_ident)), "OK",
            description="identity-only user once the key policy delegates to the account")
    back = kms.decrypt(CiphertextBlob=box["ct"])
    assert back["Plaintext"] == plaintext, "the delegated grant must produce real, decryptable ciphertext"

    # --- Re-break: the first refusal could in principle have predated the identity policy's
    # propagation. This one cannot -- the same identity policy was just proven effective -- so it
    # isolates the key policy's delegation as the only thing standing between the Allow and the key.
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=key_policy("*", delegate=False))
    _settle(lambda: _outcome(lambda: enc(as_ident)), "AccessDeniedException",
            description="identity-only user once the delegation is withdrawn again")
    rebroken = _error(lambda: enc(as_ident))
    assert rebroken == refusal, (
        f"the withdrawn delegation must refuse with exactly {refusal!r} again; got {rebroken!r}"
    )
    control = _outcome(lambda: enc(as_res))
    assert control == "OK", f"the key-policy-only user is unaffected by the delegation; got {control!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
