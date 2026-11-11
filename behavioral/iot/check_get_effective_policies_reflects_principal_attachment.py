"""get-effective-policies-reflects-principal-attachment."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-effective-policies-reflects-principal-attachment"
GROUP = 'policy-lifecycle'
SERVICES = ['iot']


def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    IoT propagates registry writes asynchronously, so early reads can raise
    ResourceNotFoundException.
    """

    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) if it raises ClientError. An unexpected
    success raises, so a target that accepts the call cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _delete_certificate(iot, cert_id):
    """Teardown: detach policies/things, deactivate, then force-delete; a missing certificate is clean."""
    try:
        cert_arn = iot.describe_certificate(certificateId=cert_id)[
            "certificateDescription"
        ]["certificateArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        cert_arn = None
    if cert_arn:
        try:
            for p in iot.list_attached_policies(target=cert_arn).get("policies", []):
                iot.detach_policy(policyName=p["policyName"], target=cert_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            for t in iot.list_principal_things(principal=cert_arn).get("things", []):
                try:
                    iot.detach_thing_principal(thingName=t, principal=cert_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_certificate(certificateId=cert_id, forceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_policy(iot, name):
    """Best-effort teardown: delete non-default versions, detach targets, then delete a policy."""
    try:
        for v in iot.list_policy_versions(policyName=name).get("policyVersions", []):
            if not v.get("isDefaultVersion"):
                try:
                    iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        for t in iot.list_targets_for_policy(policyName=name).get("targets", []):
            iot.detach_policy(policyName=name, target=t)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        iot.delete_policy(policyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetEffectivePolicies resolves only the principal's own attached policy (default version,
    never another certificate's) and shrinks on detach; a thingName-only call is refused, since
    thingName is policy-variable context, not an identity, and adds nothing to the result.
    """
    iot = ctx.client("iot")
    tag = [{"Key": "sim2real", "Value": "true"}]

    created = iot.create_keys_and_certificate(setAsActive=True)
    cert_id = created["certificateId"]
    cert_arn = created["certificateArn"]
    ctx.on_cleanup(lambda _n=cert_id: _delete_certificate(iot, _n))

    other = iot.create_keys_and_certificate(setAsActive=True)
    other_id = other["certificateId"]
    other_arn = other["certificateArn"]
    ctx.on_cleanup(lambda _n=other_id: _delete_certificate(iot, _n))

    def names_for(**kwargs):
        return sorted(
            p["policyName"] for p in iot.get_effective_policies(**kwargs)["effectivePolicies"]
        )

    assert names_for(principal=cert_arn) == [], (
        f"a principal with no attachment must have no effective policies, got {names_for(principal=cert_arn)}"
    )

    mine = ctx.unique_name("sim2real-behav-policy-effective-")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}],
    }
    iot.create_policy(policyName=mine, policyDocument=json.dumps(doc), tags=tag)
    ctx.on_cleanup(lambda _n=mine: _delete_policy(iot, _n))

    foreign = ctx.unique_name("sim2real-behav-policy-foreign-")
    iot.create_policy(policyName=foreign, policyDocument=json.dumps(doc), tags=tag)
    ctx.on_cleanup(lambda _n=foreign: _delete_policy(iot, _n))

    iot.attach_policy(policyName=mine, target=cert_arn)
    iot.attach_policy(policyName=foreign, target=other_arn)

    effective = _eventually(
        lambda: iot.get_effective_policies(principal=cert_arn)["effectivePolicies"],
        lambda ps: any(p["policyName"] == mine for p in ps),
        timeout_s=60,
    )
    resolved = {p["policyName"]: p for p in effective}
    assert sorted(resolved) == [mine], (
        f"exactly the attached policy must be effective for the principal, got {sorted(resolved)}"
    )
    assert foreign not in resolved, (
        f"a policy attached to a DIFFERENT certificate must not be effective here: {sorted(resolved)}"
    )
    assert json.loads(resolved[mine]["policyDocument"]) == doc, (
        f"the effective policy must carry the default version's document, got {resolved[mine]['policyDocument']}"
    )
    assert set(resolved[mine]) == {"policyName", "policyArn", "policyDocument"}, (
        f"an effectivePolicies entry is exactly name+arn+document, got {sorted(resolved[mine])}"
    )
    assert resolved[mine]["policyArn"].endswith(f":policy/{mine}"), (
        f"the entry must carry the policy's own ARN, got {resolved[mine]['policyArn']!r}"
    )
    # Symmetric isolation: the other certificate resolves to exactly the other policy, so the
    # first result was not "every policy in the account" filtered by luck.
    assert names_for(principal=other_arn) == [foreign], (
        f"the second certificate must resolve to exactly its own policy, got "
        f"{names_for(principal=other_arn)}"
    )

    # --- The identity parameter contract. A thing attached to the certificate is deliberately
    # created first, so every refusal below happens with the transitive path fully in place.
    thing = ctx.unique_name("sim2real-behav-thing-effective-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))
    iot.attach_thing_principal(thingName=thing, principal=cert_arn)
    ctx.on_cleanup(
        lambda _t=thing, _p=cert_arn: iot.detach_thing_principal(thingName=_t, principal=_p)
    )
    assert cert_arn in iot.list_thing_principals(thingName=thing)["principals"], (
        "precondition: the thing must really be attached to the certificate that holds the policy"
    )

    # thingName is NOT an identity: naming only the thing is refused even though that thing is
    # attached to a certificate that has an effective policy.
    # (a 200 here would mean an invented thing->certificate->policy walk)
    thing_only = _error(lambda: iot.get_effective_policies(thingName=thing))
    assert thing_only[0] == "InvalidRequestException", (
        f"a missing identity is InvalidRequestException, got {thing_only[0]!r}"
    )
    assert thing_only[1] == "Both principal and CognitoIdentityPoolId can not be null.", (
        f"the refusal must name the two acceptable identities; real AWS says \"Both principal and "
        f'CognitoIdentityPoolId can not be null." and this said {thing_only[1]!r}'
    )
    # The identical refusal with no arguments at all: the thing was never even considered.
    no_args = _error(lambda: iot.get_effective_policies())
    assert no_args == thing_only, (
        f"passing only thingName must be refused exactly as passing nothing is, got {no_args!r} "
        f"vs {thing_only!r} — the two being different would mean thingName is a lookup key"
    )
    # ...and the other acceptable identity is a Cognito identity pool, which is really resolved.
    cognito = _error(
        lambda: iot.get_effective_policies(
            cognitoIdentityPoolId=f"{ctx.region}:00000000-0000-0000-0000-000000000000"
        )
    )
    assert cognito[0] == "ResourceNotFoundException", (
        f"an absent Cognito identity pool must be a ResourceNotFoundException, got {cognito!r}"
    )
    assert cognito[1] == f"IdentityPool '{ctx.region}:00000000-0000-0000-0000-000000000000' not found.", (
        f"the 404 must name the identity pool, got {cognito[1]!r}"
    )

    # thingName alongside a principal is accepted, and contributes NOTHING to the resolution.
    assert names_for(principal=cert_arn, thingName=thing) == [mine], (
        f"thingName is optional context, not a filter: with the principal it must return the "
        f"principal's own policies, got {names_for(principal=cert_arn, thingName=thing)}"
    )
    assert names_for(principal=other_arn, thingName=thing) == [foreign], (
        f"the thing is attached to the FIRST certificate, so pairing it with the second "
        f"certificate must still resolve the second certificate's policies — there is no "
        f"transitive walk through the thing; got "
        f"{names_for(principal=other_arn, thingName=thing)}"
    )

    # Detach shrinks the set back to empty.
    iot.detach_policy(policyName=mine, target=cert_arn)
    after = _eventually(
        lambda: names_for(principal=cert_arn),
        lambda ns: mine not in ns,
        timeout_s=60,
    )
    assert after == [], f"detaching the only policy must leave no effective policies, got {after}"
    assert names_for(principal=cert_arn, thingName=thing) == [], (
        f"the thing attachment survives the policy detach and still contributes nothing, got "
        f"{names_for(principal=cert_arn, thingName=thing)}"
    )
    # Control: the untouched certificate still resolves, so the detach was scoped to one target.
    assert names_for(principal=other_arn) == [foreign], (
        f"detaching {mine} from one certificate must not disturb the other, got "
        f"{names_for(principal=other_arn)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
