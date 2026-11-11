"""unmask-without-permission-denied-while-masked-read-still-served."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unmask-without-permission-denied-while-masked-read-still-served"
GROUP = 'data-protection'
SERVICES = ['logs']

_EMAIL = "jane.doe@example.com"
_MASKED_MARKER = "*"
_SENSITIVE_PREFIX = "login attempt from user "


def _now_ms() -> int:
    return int(time.time() * 1000)


def _client_error(fn):
    """The exact AWS error (code, message), or an AssertionError on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "GetLogEvents(unmask=True) was expected to be DENIED and it SUCCEEDED; the caller was "
        "served de-identified data it has no permission to see"
    )


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _policy_document(name):
    """Mask the built-in EmailAddress identifier.

    PutDataProtectionPolicy requires the Audit statement beside Deidentify; findings go nowhere.
    """
    return json.dumps(
        {
            "Name": name,
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit-email",
                    "DataIdentifier": [
                        "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
                    ],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "mask-email",
                    "DataIdentifier": [
                        "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
                    ],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A principal that may read a protected log group but lacks ``logs:Unmask`` is denied
    ``unmask=True`` and never sees the raw identifier, yet gets the masked event from the same
    call without it; granting logs:Unmask to the same role then makes the unmask succeed.
    """
    svc = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-unmaskdeny-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    policy_name = ctx.unique_name("sim2real-behav-dpp-")
    svc.put_data_protection_policy(
        logGroupIdentifier=group, policyDocument=_policy_document(policy_name)
    )
    ctx.on_cleanup(
        lambda _n=group: svc.delete_data_protection_policy(logGroupIdentifier=_n)
    )

    # Masking is applied at INGEST, and PutDataProtectionPolicy returns before the
    # ingest path is necessarily using the policy, so an event written too early is
    # stored unredacted and no read-path polling will ever mask it. The only reliable
    # barrier is a canary in a throwaway stream, ingested until it comes back masked.
    canary_stream = ctx.unique_name("sim2real-behav-canary-")
    svc.create_log_stream(logGroupName=group, logStreamName=canary_stream)

    def _canary():
        svc.put_log_events(
            logGroupName=group,
            logStreamName=canary_stream,
            logEvents=[{"timestamp": _now_ms(), "message": f"canary {_EMAIL} canary"}],
        )
        resp = svc.get_log_events(
            logGroupName=group, logStreamName=canary_stream, startFromHead=True
        )
        return [e["message"] for e in resp.get("events", [])]

    _poll_until(
        _canary,
        lambda msgs: any(_EMAIL not in m and _MASKED_MARKER in m for m in msgs),
        timeout_s=180,
        interval_s=5.0,
        description="the data protection policy becomes live on the ingest path",
    )

    sensitive = f"{_SENSITIVE_PREFIX}{_EMAIL} failed"
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": sensitive}],
    )

    def _privileged_read(**kwargs):
        resp = svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True, **kwargs
        )
        return [e["message"] for e in resp.get("events", [])]

    masked = _poll_until(
        lambda: _privileged_read(),
        lambda msgs: len(msgs) == 1 and _EMAIL not in msgs[0],
        timeout_s=90,
        interval_s=3.0,
        description="the sensitive event is readable and masked for the privileged caller",
    )
    assert _EMAIL not in masked[0], (
        f"setup: the event must be stored masked before the permission legs mean anything, got "
        f"{masked[0]!r}"
    )

    # --- A principal that may READ the group but has no logs:Unmask.
    role_name = ctx.unique_name("sim2real-behav-nounmask-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav logs:Unmask denial scenario",
        Tags=[{"Key": "sim2real", "Value": "unmask-without-permission-denied"}],
    )

    def _delete_role(_n=role_name):
        for pname in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=_n, PolicyName=pname)
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)

    inline_name = "sim2real-behav-read-without-unmask"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        # logs:Unmask is ABSENT -- the one broken thing. Nothing is
                        # denied explicitly, so the deny under test is IAM's implicit
                        # one, which is the shape a real caller hits.
                        "Action": [
                            "logs:GetLogEvents",
                            "logs:FilterLogEvents",
                            "logs:DescribeLogStreams",
                        ],
                        "Resource": [
                            f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}",
                            f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:*",
                        ],
                    }
                ],
            }
        ),
    )

    deadline = time.monotonic() + 60
    creds = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName="sim2real-behav-nounmask",
            )["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly-created role {role_name!r} never succeeded within 60s, so the "
        f"unmask permission boundary could not be exercised: {last_exc!r}"
    )

    # The assumed role's client signs as that role against the same target; nothing is
    # exported, so the ambient credential chain is untouched.
    limited = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-behav-nounmask"
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    def _limited_read(**kwargs):
        resp = limited.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True, **kwargs
        )
        return [e["message"] for e in resp.get("events", [])]

    # --- Positive control FIRST, which doubles as the bounded retry past IAM
    # propagation: the same principal, the same operation, WITHOUT unmask, must
    # succeed. Until the inline policy is effective this raises AccessDenied, and that
    # is propagation rather than the property under test -- so it is retried, not
    # asserted.
    def _control_attempt():
        try:
            return _limited_read()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    control = _poll_until(
        _control_attempt,
        lambda r: isinstance(r, list) and len(r) == 1,
        timeout_s=120,
        interval_s=5.0,
        description=(
            "the limited principal's inline policy becomes effective and its plain GetLogEvents "
            "returns the one stored event"
        ),
    )
    assert control == [masked[0]], (
        "positive control: the limited principal must be able to read the group WITHOUT unmask, "
        f"and must see exactly the masked event {masked[0]!r}; got {control!r} -- if this fails "
        "the denial below would only prove the role cannot read the group at all"
    )
    assert _EMAIL not in control[0], (
        f"the masked read served to the limited principal contains the raw identifier: "
        f"{control[0]!r}"
    )
    assert control[0].startswith(_SENSITIVE_PREFIX), (
        f"only the matched data identifier may be redacted for the limited principal, got "
        f"{control[0]!r}"
    )

    # --- The negative: one parameter changes, and the answer must change with it.
    code, message = _client_error(lambda: _limited_read(unmask=True))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for GetLogEvents(unmask=True) by a principal without "
        f"logs:Unmask, got {code!r}"
    )
    expected_get = (
        f"User: {session_arn} is not authorized to perform: logs:Unmask on resource: "
        f"{group_arn}:log-stream: because no identity-based policy allows the logs:Unmask action"
    )
    assert message == expected_get, (
        f"GetLogEvents(unmask=True) denial message: expected {expected_get!r}, got {message!r}"
    )

    # --- Effect absent: the raw identifier reached that principal through nothing.
    filtered_code, filtered_message = _client_error(
        lambda: limited.filter_log_events(logGroupName=group, unmask=True)
    )
    assert filtered_code == "AccessDeniedException", (
        f"FilterLogEvents(unmask=True) is the second read path and must be guarded by the same "
        f"permission; got {filtered_code!r} -- the redaction hook is easy to wire into only one"
    )
    expected_filter = (
        f"User: {session_arn} is not authorized to perform: logs:Unmask on resource: "
        f"{group_arn} because no identity-based policy allows the logs:Unmask action"
    )
    assert filtered_message == expected_filter, (
        f"FilterLogEvents(unmask=True) denial message: expected {expected_filter!r}, got "
        f"{filtered_message!r}"
    )
    everything_served = json.dumps(control)
    assert _EMAIL not in everything_served, (
        f"effect not absent: the raw identifier appears in what the unprivileged principal was "
        f"served: {everything_served!r}"
    )

    # --- The other side of the loop: with the permission, unmask really does work, so
    # the denial above is a permission decision and not a broken parameter.
    unmasked = _privileged_read(unmask=True)
    assert unmasked == [sensitive], (
        "a caller WITH logs:Unmask must recover the original event verbatim, otherwise the denial "
        f"above proves nothing about the permission; got {unmasked!r} for {[sensitive]!r}"
    )

    # --- Restore, on the SAME denied principal: grant logs:Unmask to the identical role
    # and re-issue the identical call. Without this leg, the denial above proves only that
    # *some* caller can unmask -- not that this role's specific grant is what the enforcement
    # tracks. A target that hardcodes "unmask is always denied to assumed roles" would pass
    # every earlier leg and only fail here.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-grant-unmask",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:Unmask",
                        "Resource": [
                            f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}",
                            f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:*",
                        ],
                    }
                ],
            }
        ),
    )
    def _restore_attempt():
        try:
            return _limited_read(unmask=True)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    restored = _poll_until(
        _restore_attempt,
        lambda r: isinstance(r, list) and r == [sensitive],
        timeout_s=90,
        interval_s=3.0,
        description=(
            "granting logs:Unmask to the SAME denied role becomes effective and its identical "
            "GetLogEvents(unmask=True) call now succeeds"
        ),
    )
    assert restored == [sensitive], (
        "restore: granting logs:Unmask to the identical role must make the identical "
        f"GetLogEvents(unmask=True) call succeed and recover the original; got {restored!r} for "
        f"{[sensitive]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
