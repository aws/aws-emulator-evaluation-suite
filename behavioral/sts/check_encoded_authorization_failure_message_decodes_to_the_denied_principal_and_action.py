"""encoded-authorization-failure-message-decodes-to-the-denied-principal-and-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encoded-authorization-failure-message-decodes-to-the-denied-principal-and-action"
GROUP = 'error-semantics'
SERVICES = ['sts']

_ENCODED_MARKER = "Encoded authorization failure message:"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A DryRun RunInstances denied by a session-policy Deny carries an encoded message that decodes
    to the denied principal, action, explicitDeny and a matching DENY statement; the same DryRun
    without the Deny returns DryRunOperation, so authorization was reached and nothing launched."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # CREDENTIAL SAFETY. Minted credentials are NEVER written to os.environ and never appear in an
    # assertion message or a diagnostic; assertions are on structure and on behaviour.

    def _client_with_credentials(service, creds, region=None):
        return ctx.client(service, region=region, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    succeeded = "(the call succeeded)"  # no error code can equal this

    def _error_code(fn):
        """The error CODE of a failing call, or ``succeeded`` if it SUCCEEDED, a value no error
        code can equal, so an unexpected success never reads as a naming difference."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return succeeded

    def _error_response(fn):
        """The whole error RESPONSE of a failing call, or one whose code is ``succeeded`` if the
        call succeeded. Used where the assertion needs the message body as well as the code."""
        try:
            fn()
        except ClientError as exc:
            return exc.response
        return {"Error": {"Code": succeeded, "Message": ""}}

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        """Bounded poll to a condition. Raises on deadline miss -- never a bare sleep."""
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=240.0, what="call"):
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica, so a single success after
        polling past InvalidClientTokenId can still be followed by a transient 403; polling on the
        exact expected success is the only race-free barrier."""
        return _poll(lambda: _error_code(fn), lambda c: c == succeeded,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`. Only ever called after a positive
        control on the same session has proven the credential live, so a permissive
        implementation simply never reaches the condition and the deadline miss IS the verdict."""
        return _poll(lambda: _error_code(fn), lambda c: c == expected,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became refused with {expected}")

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _error_code(lambda: probe.get_caller_identity()), lambda c: c == succeeded,
              timeout_s=180.0, interval_s=2.0,
              description="temporary credentials became active")

    def _tags_kv(scenario):
        return [{"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": scenario}]

    account = sts.get_caller_identity()["Account"]

    def _trust_root():
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": ["sts:AssumeRole"]}]}

    def _allow(actions, resource="*"):
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resource}]}

    def _drop_role(role_name):
        # Attached managed policies, inline policies AND a permissions boundary all block
        # delete_role, so all three come off first; then poll to actual disappearance.
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        if iam.get_role(RoleName=role_name)["Role"].get("PermissionsBoundary"):
            iam.delete_role_permissions_boundary(RoleName=role_name)
        iam.delete_role(RoleName=role_name)
        _poll(lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    def _drop_role_if_present(role_name):
        """As _drop_role, but a no-op if the role is already gone -- for a check that deletes the
        role itself as part of its subject. Never a bare `lambda: None`: it really does delete."""
        if _error_code(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE. IAM is eventually consistent
        about a role ARN's usability as a trust-policy principal ("Invalid principal in policy")
        and about a just-deleted name becoming free."""
        try:
            return iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
                MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _drop_bucket(bucket, client=None):
        c = client or s3
        for page in c.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                c.delete_object(Bucket=bucket, Key=obj["Key"])
        c.delete_bucket(Bucket=bucket)
        _poll(lambda: _error_code(lambda: c.head_bucket(Bucket=bucket)),
              lambda code: code in {"404", "NoSuchBucket"}, timeout_s=90.0, interval_s=2.0,
              description=f"bucket {bucket} disappeared")

    def _new_bucket(scenario, client=None, region=None):
        c = client or s3
        bucket = ctx.unique_name("sim2real-behav-sts-")
        params = {"Bucket": bucket}
        target_region = region or ctx.region
        if target_region and target_region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": target_region}
        c.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket, c))
        # Tagged so a Resource Groups Tagging API cleanup can find it.
        c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, **kw):
        """The AssumeRole response on success, or the error CODE string on failure -- so
        `result == "AccessDenied"` proves the code AND that no credentials were issued."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, **kw):
        # Trust-policy propagation is real: the first AssumeRole against a new role fails for
        # seconds. Establishing this positive control BEFORE any negative assertion is what keeps
        # a still-propagating grant from being read as a refusal.
        return _poll(lambda: _try_assume(client, role_arn, **kw), lambda r: isinstance(r, dict),
                     timeout_s=240.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")


    scenario = "sts-decode-authorization-message"

    # Resolved at runtime: a hard-coded AMI id rots, and a fake one fails InvalidAMIID.Malformed
    # before authorization is evaluated, so no encoded message would be produced.
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-") and len(ami) == 21, (
        f"the SSM public alias did not resolve to an AMI id: {ami!r}")

    instance_type = "t3.micro"

    def _dry_run(ec2_client):
        return ec2_client.run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, DryRun=True, SubnetId=ctx.network().subnet_ids[0])

    # The role's identity policy allows everything, so the DENY can only come from the session
    # policy -- that is what isolates the variable.
    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_root()),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(_allow(["*"])))

    denying_policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:DescribeInstances", "ec2:RunInstances"],
         "Resource": "*"},
        {"Effect": "Deny", "Action": ["ec2:RunInstances"], "Resource": "*"}]}
    permissive_policy = _allow(["ec2:DescribeInstances", "ec2:RunInstances"])

    denied_session = _wait_assumable(sts, role_arn, Policy=json.dumps(denying_policy))
    _wait_creds_active(denied_session["Credentials"])
    assumed_role_arn = denied_session["AssumedRoleUser"]["Arn"]
    assumed_role_id = denied_session["AssumedRoleUser"]["AssumedRoleId"]
    denied_ec2 = _client_with_credentials("ec2", denied_session["Credentials"])

    # --- SECOND CONTROL, established first: the session policy's ALLOW half works, so the session is
    # live and usable and the refusal below cannot be an unpropagated grant.
    _poll_allowed(lambda: denied_ec2.describe_instances(MaxResults=5),
                  what="ec2:DescribeInstances, the ALLOW half of the same session policy")
    described = denied_ec2.describe_instances(MaxResults=5)
    assert described["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "the session policy's Allow half did not work, so the Deny cannot be isolated as the cause "
        f"of anything: {described.get('ResponseMetadata')!r}")

    # --- Break exactly one thing: the action the session policy explicitly denies.
    failure = _poll(
        lambda: _error_response(lambda: _dry_run(denied_ec2)),
        lambda r: isinstance(r, dict)
        and r.get("Error", {}).get("Code") == "UnauthorizedOperation",
        timeout_s=240.0, interval_s=3.0,
        description="the denied RunInstances DryRun became UnauthorizedOperation")
    code = failure["Error"]["Code"]
    assert code == "UnauthorizedOperation", (
        f"a RunInstances DryRun denied by a session policy must be UnauthorizedOperation, got "
        f"{code!r}")

    message = failure["Error"].get("Message") or ""
    assert _ENCODED_MARKER in message, (
        "the denial carried no encoded authorization message, so the decode path is unreachable and "
        f"the suite's existing skip would be vindicated; the message was {message!r}")
    encoded = message.split(_ENCODED_MARKER, 1)[1].strip()
    assert encoded, (
        f"the encoded authorization message was present but empty: {message!r}")
    # The blob is opaque and minted per failure; its decoded content is asserted below.
    assert message == (
        f"You are not authorized to perform this operation. User: {assumed_role_arn} is not "
        f"authorized to perform: ec2:RunInstances on resource: "
        f"arn:aws:ec2:{ctx.region}:{account}:instance/* with an explicit deny in a session "
        f"policy. {_ENCODED_MARKER} {encoded}"
    ), message

    # Decode with the caller's own credentials, independent of the session under test.
    decoded = json.loads(
        sts.decode_authorization_message(EncodedMessage=encoded)["DecodedMessage"])

    assert decoded["allowed"] is False, (
        f"the decoded message must report the request as not allowed; got {decoded.get('allowed')!r} "
        f"in {decoded!r}")
    assert decoded["explicitDeny"] is True, (
        "the denial came from an explicit Deny in a session policy, so the decoded message must say "
        f"so; explicitDeny was {decoded.get('explicitDeny')!r}")

    context = decoded["context"]
    assert context["principal"]["arn"] == assumed_role_arn, (
        "the decoded message names the wrong principal: "
        f"{context['principal']['arn']!r} != {assumed_role_arn!r}")
    assert context["principal"]["id"] == assumed_role_id, (
        "the decoded principal id must be the AssumedRoleId AssumeRole returned: "
        f"{context['principal']['id']!r} != {assumed_role_id!r}")
    # AWS puts the BARE operation name here and the service-qualified form in matchedStatements.
    assert context["action"] == "RunInstances", (
        f"the decoded context action must be the bare operation name; got {context['action']!r}")
    assert context["resource"].startswith(f"arn:aws:ec2:{ctx.region}:") \
        and context["resource"].endswith(":instance/*"), (
        "the decoded context resource must be the EC2 instance ARN the request would have created "
        f"in {ctx.region}; got {context['resource']!r}")
    condition_keys = {c["key"] for c in context["conditions"]["items"]}
    assert "ec2:InstanceType" in condition_keys, (
        "the decoded request context must carry the condition keys EC2 derived from the request, "
        f"which is what makes this a diagnostic rather than an echo; got {sorted(condition_keys)!r}")
    instance_type_values = {
        v["value"] for c in context["conditions"]["items"] if c["key"] == "ec2:InstanceType"
        for v in c["values"]["items"]}
    assert instance_type_values == {instance_type}, (
        "the decoded ec2:InstanceType must be the type THIS request asked for, which is how the blob "
        f"is shown to describe this failure and not a recorded one; got {instance_type_values!r}")

    matched = decoded["matchedStatements"]["items"]
    assert len(matched) == 1, (
        "exactly one statement -- the session policy's Deny -- must have matched; got "
        f"{len(matched)}: {matched!r}")
    assert matched[0]["effect"] == "DENY", (
        f"the matched statement must be the DENY; got effect {matched[0]['effect']!r}")
    assert [a["value"] for a in matched[0]["actions"]["items"]] == ["ec2:RunInstances"], (
        "the matched DENY statement must name the service-qualified action from the session policy; "
        f"got {matched[0]['actions']['items']!r}")
    assert [p["value"] for p in matched[0]["principals"]["items"]] == [assumed_role_id], (
        "the matched DENY statement must name the principal id of THIS session; got "
        f"{matched[0]['principals']['items']!r}")

    # --- POSITIVE CONTROL: the same request, the same role, a session policy WITHOUT the Deny. It
    # must report DryRunOperation, which proves the request was well-formed and permitted -- so the
    # failure above was authorization, not validation. Without this leg an implementation that
    # rejects every RunInstances for any reason passes the negative.
    permitted_session = _wait_assumable(sts, role_arn, Policy=json.dumps(permissive_policy))
    _wait_creds_active(permitted_session["Credentials"])
    permitted_ec2 = _client_with_credentials("ec2", permitted_session["Credentials"])
    control_code = _poll(
        lambda: _error_code(lambda: _dry_run(permitted_ec2)),
        lambda c: c == "DryRunOperation", timeout_s=240.0, interval_s=3.0,
        description="the permitted RunInstances DryRun became DryRunOperation")
    assert control_code == "DryRunOperation", (
        "positive control: an ALLOWED RunInstances DryRun must report DryRunOperation, got "
        f"{control_code!r} -- otherwise the earlier failure may have been request validation rather "
        "than authorization, and the decoded message would describe the wrong thing")

    # --- EFFECT ABSENT: neither path launched anything. DryRun is the reason, and this is the
    # assertion that proves it rather than assuming it.
    reservations = []
    for page in ctx.client("ec2").get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name",
                      "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]}]):
        reservations.extend(page.get("Reservations", []))
    launched = [i["InstanceId"] for r in reservations for i in r.get("Instances", [])
                if i.get("ImageId") == ami]
    assert launched == [], (
        "a DryRun must never create an instance, on the denied path or the permitted one; instances "
        f"from image {ami!r} are present: {launched!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
