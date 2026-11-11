"""managed-admin-password-creates-a-rotatable-secret-that-cannot-be-deleted."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-admin-password-creates-a-rotatable-secret-that-cannot-be-deleted"
GROUP = "representation"
SERVICES = ["redshift", "secretsmanager"]


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")
MASTER_USERNAME = "adminuser"
DB_NAME = "devdb"
_NOT_FOUND_CLUSTER = ("ClusterNotFound", "ClusterNotFoundFault")
_INVALID_STATE = ("InvalidClusterState", "InvalidClusterStateFault")
_CLUSTER_DEADLINE_S = 900
_DELETE_CLUSTER_DEADLINE_S = 300
# The secret is created as part of cluster provisioning, so it is normally there the moment the
# cluster is available; the poll exists so a lagging propagation is a wait, not a failure.
_SECRET_DEADLINE_S = 300
# Rotating the admin password drives a cluster modification.
_ROTATION_DEADLINE_S = 600
_BACK_TO_AVAILABLE_DEADLINE_S = 600
_MANAGED_SECRET_REFUSAL_HINTS = ("another service", "owned by", "managed by", "service-linked")
_DOCUMENTED_ROTATION_DAYS = 30


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _message_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message") or ""
    return str(exc)


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure noise under
    parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _retry_invalid_state(fn, deadline_s=120):
    """Call *fn*, also retrying InvalidClusterState: a ModifyCluster shortly after `available` can
    be refused with a transient "This Cluster can not be modified. Please try again."."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return _retrying(fn)
        except ClientError as exc:
            if _code_of(exc) not in _INVALID_STATE or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _rejected(fn, what):
    """(error_code, message) for a call that MUST fail; RAISES on unexpected success so acceptance
    never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return _code_of(exc), _message_of(exc)
    raise AssertionError(
        f"{what} must be REJECTED, but it succeeded and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_until(probe, done, timeout_s, interval_s, what="condition", ctx=None):
    """Poll *probe* every *interval_s* until *done*. RAISES on timeout, which is bounded by
    *timeout_s* and the check's remaining budget; never returns its last value."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if done(observed):
            return observed
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"waiting for {what}: the run budget ended first; not graded")
            raise AssertionError(
                f"timed out after {timeout_s:.0f}s waiting for {what}; last observed={observed!r}"
            )
        time.sleep(interval_s)


def _node_type(rs, cluster_type="single-node"):
    """Cheapest orderable node type for *cluster_type* in this region, read off the account."""
    available = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = _retrying(lambda: rs.describe_orderable_cluster_options(**kwargs))
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(
                f"no orderable {cluster_type} options in {rs.meta.region_name}; "
                f"DescribeOrderableClusterOptions returned nothing usable"
            )
        chosen = sorted(available)[0]
    return chosen


def _cluster_params(rs, cluster_id, **overrides):
    """One node, private, 1-day snapshot retention (RA3 refuses 0), no admin password and no
    secret KMS key: naming aws/secretsmanager explicitly needs kms:CreateGrant, which the
    AWS-managed key's policy does not delegate to the caller."""
    params = dict(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(rs),
        MasterUsername=MASTER_USERNAME,
        ManageMasterPassword=True,
        ClusterType="single-node",
        DBName=DB_NAME,
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
    )
    params.update(overrides)
    return params


def _create_cluster(rs, cluster_id, **overrides):
    """CreateCluster with a bounded retry on association races and on the first-use
    "Unable to assume the SLR" refusal while Redshift's service-linked role propagates."""
    deadline = time.monotonic() + 180
    while True:
        try:
            return _retrying(
                lambda: rs.create_cluster(**_cluster_params(rs, cluster_id, **overrides))
            )
        except ClientError as exc:
            slr_race = _code_of(exc) == "InvalidParameterValue" and "SLR" in _message_of(exc)
            if (
                not (slr_race or _code_of(exc) in _INVALID_STATE + ("InvalidIamRoleFault",))
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


def _describe_cluster(rs, cluster_id):
    try:
        resp = _retrying(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    except ClientError as exc:
        if _code_of(exc) in _NOT_FOUND_CLUSTER:
            return None
        raise
    clusters = resp.get("Clusters", [])
    return clusters[0] if clusters else None


def _cluster_status(rs, cluster_id):
    cluster = _describe_cluster(rs, cluster_id)
    return cluster["ClusterStatus"] if cluster else None


def _wait_for_cluster_available(rs, cluster_id, timeout_s=_CLUSTER_DEADLINE_S, ctx=None):
    terminal = {
        "available",
        "incompatible-network",
        "incompatible-parameters",
        "incompatible-hsm",
        "insufficient-capacity",
        "hardware-failure",
        None,
    }
    status = _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=2,
        what=f"cluster {cluster_id} to reach a terminal creation state",
        ctx=ctx,
    )
    assert status == "available", (
        f"cluster {cluster_id} reached terminal state {status!r}, expected 'available'"
    )
    return status


def _delete_cluster(rs, cluster_id):
    """Cost-leak teardown. Anything OTHER than not-found / wrong-state / throttle RAISES."""
    deadline = time.monotonic() + _DELETE_CLUSTER_DEADLINE_S
    while True:
        try:
            rs.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code in _NOT_FOUND_CLUSTER:
                return
            if code not in _INVALID_STATE + _THROTTLE or time.monotonic() >= deadline:
                raise
        time.sleep(3)


def _force_delete_secret(sm, secret_id):
    """Teardown for the UNMANAGED control secret only. Not-found is success; anything else RAISES so
    a leaked secret is loud."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if _code_of(exc) != "ResourceNotFoundException":
            raise


def _current_version(sm, arn):
    """The version id currently staged AWSCURRENT, read off DescribeSecret rather than from
    GetSecretValue, so the two surfaces have to agree."""
    stages = _retrying(lambda: sm.describe_secret(SecretId=arn)).get("VersionIdsToStages") or {}
    current = [vid for vid, staged in stages.items() if "AWSCURRENT" in staged]
    assert len(current) == 1, (
        f"exactly one version of {arn!r} must be staged AWSCURRENT, got {stages!r}"
    )
    return current[0]


def _secret_json(sm, arn, expected_stages=(("AWSCURRENT",),)):
    """The secret's payload as a dict, plus the version it came from.

    Right after RotateSecret the new AWSCURRENT version may still carry AWSPENDING until the
    rotation finishes, so callers pass every stage set they accept."""
    value = _retrying(lambda: sm.get_secret_value(SecretId=arn))
    accepted = [sorted(stages) for stages in expected_stages]
    assert sorted(value.get("VersionStages") or []) in accepted, (
        f"GetSecretValue with no stage must serve exactly one of {accepted!r}, got "
        f"{value.get('VersionStages')!r}"
    )
    raw = value.get("SecretString")
    assert raw, (
        f"a Redshift-managed admin secret must carry a SecretString, not binary; got {value!r}"
    )
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise AssertionError(
            f"the managed admin secret must be a JSON object; it did not parse: {exc}"
        ) from exc
    assert isinstance(payload, dict), (
        f"the managed admin secret must be a JSON OBJECT, got {type(payload).__name__}"
    )
    return payload, value["VersionId"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Asking Redshift to manage the admin password creates a Redshift-owned Secrets Manager secret
    with rotation on, which DeleteSecret refuses and RotateSecret rotates in place; an explicit
    admin password alongside that request is refused."""
    rs = ctx.client("redshift")
    sm = ctx.client("secretsmanager")

    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id, got {account!r}"
    )
    scenario = "rs-managed-secret"
    tag_set = [{"Key": "sim2real", "Value": scenario}]

    cluster_id = ctx.unique_name("sim2real-behav-rs-secret-")
    # A provisioned Redshift cluster is the single most expensive leak in this service, so this is
    # registered before the identifier is used anywhere.
    ctx.on_cleanup(lambda: _delete_cluster(rs, cluster_id))
    created = _create_cluster(rs, cluster_id, Tags=tag_set)
    assert created["Cluster"].get("MasterUserPassword") is None, (
        f"CreateCluster must never echo a password back, got "
        f"{created['Cluster'].get('MasterUserPassword')!r}"
    )
    _wait_for_cluster_available(rs, cluster_id, ctx=ctx)

    cluster = _wait_until(
        lambda: _describe_cluster(rs, cluster_id),
        lambda c: bool(c and c.get("MasterPasswordSecretArn")),
        timeout_s=_SECRET_DEADLINE_S,
        interval_s=2,
        what=f"cluster {cluster_id} to report a MasterPasswordSecretArn",
        ctx=ctx,
    )
    secret_arn = cluster["MasterPasswordSecretArn"]
    # With the default aws/secretsmanager key the KMS key id is omitted, not echoed.
    assert cluster.get("MasterPasswordSecretKmsKeyId") is None, (
        f"CreateCluster was given no MasterPasswordSecretKmsKeyId, so the default "
        f"aws/secretsmanager key encrypts the secret and DescribeClusters must omit this field; "
        f"got {cluster.get('MasterPasswordSecretKmsKeyId')!r}"
    )
    # The arn is derived from the caller's own account and region — nothing hardcoded.
    arn_parts = secret_arn.split(":")
    assert arn_parts[:3] == ["arn", "aws", "secretsmanager"], (
        f"MasterPasswordSecretArn must be a Secrets Manager arn, got {secret_arn!r}"
    )
    assert arn_parts[3] == ctx.region, (
        f"the secret must live in the cluster's own region {ctx.region!r}, got {arn_parts[3]!r} "
        f"from {secret_arn!r}"
    )
    assert arn_parts[4] == account, (
        f"the secret must live in the caller's own account {account!r}, got {arn_parts[4]!r} from "
        f"{secret_arn!r}"
    )

    # ---- terminal read at the consumer: Secrets Manager owns up to the secret ----
    described = _retrying(lambda: sm.describe_secret(SecretId=secret_arn))
    assert described["ARN"] == secret_arn, (
        f"DescribeSecret must resolve the arn Redshift reported: asked for {secret_arn!r}, got "
        f"{described.get('ARN')!r}"
    )
    assert described.get("OwningService") == "redshift", (
        f"the secret must be marked as owned by Redshift so Secrets Manager refuses direct "
        f"mutation of it; OwningService was {described.get('OwningService')!r}"
    )
    assert described.get("DeletedDate") is None, (
        f"a live cluster's secret must not be scheduled for deletion, got "
        f"{described.get('DeletedDate')!r}"
    )
    # DescribeSecret also omits KmsKeyId for the aws/secretsmanager default key.
    assert described.get("KmsKeyId") is None, (
        f"the secret was created with no explicit KmsKeyId, so Secrets Manager's own DescribeSecret "
        f"must omit it too (default aws/secretsmanager key); got {described.get('KmsKeyId')!r}"
    )
    assert described.get("RotationEnabled") is True, (
        f"Redshift creates the managed secret with rotation ENABLED by default; DescribeSecret "
        f"said RotationEnabled={described.get('RotationEnabled')!r}"
    )
    rotation_rules = described.get("RotationRules") or {}
    assert (
        rotation_rules.get("AutomaticallyAfterDays") == _DOCUMENTED_ROTATION_DAYS
        or str(_DOCUMENTED_ROTATION_DAYS) in (rotation_rules.get("ScheduleExpression") or "")
    ), (
        f"the default rotation schedule is documented as every {_DOCUMENTED_ROTATION_DAYS} days "
        f"and must show up in RotationRules; got {rotation_rules!r}"
    )

    # An independent read at the consumer through a DIFFERENT operation: the secret is discoverable
    # by its owning service, not just by the arn Redshift handed over.
    found, token = [], None
    while True:
        kwargs = {
            "Filters": [{"Key": "owning-service", "Values": ["redshift"]}],
            "MaxResults": 100,
        }
        if token:
            kwargs["NextToken"] = token
        page = _retrying(lambda: sm.list_secrets(**kwargs))
        found.extend(s["ARN"] for s in page.get("SecretList", []))
        token = page.get("NextToken")
        if not token:
            break
    assert secret_arn in found, (
        f"ListSecrets filtered to owning-service=redshift must include {secret_arn!r}; it returned "
        f"{found!r}"
    )

    payload, original_version = _secret_json(sm, secret_arn)
    assert payload.get("username") == MASTER_USERNAME, (
        f"the secret must carry the admin username CreateCluster was given: expected "
        f"{MASTER_USERNAME!r}, got {payload.get('username')!r}"
    )
    original_password = payload.get("password")
    assert isinstance(original_password, str) and original_password, (
        f"the secret must carry a generated password, got {original_password!r} "
        f"(keys present: {sorted(payload)!r})"
    )
    assert original_password != MASTER_USERNAME, (
        f"the generated password must differ from the username {MASTER_USERNAME!r}; the secret "
        f"holds the two as the same value, so nothing was generated. (The password itself is "
        f"deliberately not quoted in this message — it is a live credential.)"
    )
    assert _current_version(sm, secret_arn) == original_version, (
        f"DescribeSecret and GetSecretValue must agree on which version is AWSCURRENT: "
        f"{_current_version(sm, secret_arn)!r} vs {original_version!r}"
    )

    # ---- negative 1: Secrets Manager refuses to delete a secret Redshift owns ----
    # Positive control FIRST, on the same wiring: an ordinary secret we create deletes fine, so the
    # refusal below cannot be "DeleteSecret is denied for this caller".
    control_name = ctx.unique_name("sim2real-behav-rs-secret-control-")
    _retrying(
        lambda: sm.create_secret(
            Name=control_name,
            SecretString=json.dumps({"username": MASTER_USERNAME, "password": "unused"}),
            Tags=tag_set,
        )
    )
    ctx.on_cleanup(lambda: _force_delete_secret(sm, control_name))
    control_deleted = _retrying(
        lambda: sm.delete_secret(SecretId=control_name, ForceDeleteWithoutRecovery=True)
    )
    assert control_deleted["Name"] == control_name, (
        f"the control secret must delete cleanly, proving DeleteSecret works for this caller; got "
        f"{control_deleted!r}"
    )

    code, message = _rejected(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True),
        f"DeleteSecret on the Redshift-managed secret {secret_arn!r}",
    )
    assert code == "InvalidRequestException", (
        f"deleting a secret owned by another service must be refused InvalidRequestException, got "
        f"{code!r}: {message!r}"
    )
    assert message == f"Operation is not allowed on secret owned by {described['OwningService']}", (
        f"expected the exact InvalidRequestException message AWS returns, got {message!r}"
    )
    assert any(hint in message.lower() for hint in _MANAGED_SECRET_REFUSAL_HINTS), (
        f"the refusal must say the secret belongs to another service — that is what separates it "
        f"from a permissions failure or a bad id; got {message!r}, expected one of "
        f"{_MANAGED_SECRET_REFUSAL_HINTS!r}"
    )
    # Effect absent, via an independent read: the secret is untouched, not soft-deleted.
    survived = _retrying(lambda: sm.describe_secret(SecretId=secret_arn))
    assert survived.get("DeletedDate") is None, (
        f"the refused delete must have scheduled nothing: DeletedDate is "
        f"{survived.get('DeletedDate')!r}"
    )
    assert _current_version(sm, secret_arn) == original_version, (
        f"the refused delete must not have moved AWSCURRENT: expected {original_version!r}, got "
        f"{_current_version(sm, secret_arn)!r}"
    )

    # ---- negative 2: the two ways of setting an admin password are mutually exclusive ----
    combo_code, combo_message = _rejected(
        lambda: rs.modify_cluster(
            ClusterIdentifier=cluster_id,
            ManageMasterPassword=True,
            MasterUserPassword="Sim2RealNotAllowed1",
        ),
        "ModifyCluster carrying BOTH ManageMasterPassword=True and MasterUserPassword",
    )
    # Redshift uses InvalidParameterValue here, not InvalidParameterCombination.
    assert combo_code == "InvalidParameterValue", (
        f"'You can't use MasterUserPassword if ManageMasterPassword is true' must be enforced as "
        f"InvalidParameterValue, got {combo_code!r}: {combo_message!r}"
    )
    assert combo_message == "Your Amazon Redshift cluster is opting in to manage your password using AWS Secrets Manager. To provide your own password, opt out of managing your password with Secrets Manager.", (
        f"expected the exact InvalidParameterValue message AWS returns, got {combo_message!r}"
    )
    assert "opt out of managing your password" in combo_message.lower(), (
        f"the refusal must name the actual conflict — opting out of Secrets Manager management — "
        f"not a generic bad-parameter message; got {combo_message!r}"
    )
    # Positive control: a managed admin password without an explicit one is accepted. A bare resend
    # is refused as "No modifications were requested", so it is paired with a real change.
    _retry_invalid_state(
        lambda: rs.modify_cluster(
            ClusterIdentifier=cluster_id,
            ManageMasterPassword=True,
            AutomatedSnapshotRetentionPeriod=2,
        )
    )
    _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s == "available",
        timeout_s=_BACK_TO_AVAILABLE_DEADLINE_S,
        interval_s=2,
        what=f"cluster {cluster_id} to settle back to `available` after the retention-period modification",
        ctx=ctx,
    )
    # Effect PRESENT for the accepted modification, effect ABSENT for the refused combination: the
    # retention period moved (proving the call was not itself a no-op), the secret did not.
    unchanged = _describe_cluster(rs, cluster_id)
    assert unchanged.get("AutomatedSnapshotRetentionPeriod") == 2, (
        f"the positive control must be a REAL modification, not a no-op the target could accept "
        f"unconditionally: expected AutomatedSnapshotRetentionPeriod=2, got "
        f"{unchanged.get('AutomatedSnapshotRetentionPeriod')!r}"
    )
    assert unchanged["MasterPasswordSecretArn"] == secret_arn, (
        f"neither the refused combination nor the accepted modification may re-point the cluster at "
        f"a new secret: expected {secret_arn!r}, got {unchanged.get('MasterPasswordSecretArn')!r}"
    )
    assert _current_version(sm, secret_arn) == original_version, (
        f"and neither may rotate it: AWSCURRENT is now {_current_version(sm, secret_arn)!r}, was "
        f"{original_version!r}"
    )

    # ---- the credential is genuinely live: rotating it changes the password IN PLACE ----
    _retrying(lambda: sm.rotate_secret(SecretId=secret_arn, RotateImmediately=True))
    rotated_version = _wait_until(
        lambda: _current_version(sm, secret_arn),
        lambda vid: vid != original_version,
        timeout_s=_ROTATION_DEADLINE_S,
        interval_s=2,
        what=f"secret {secret_arn} to stage a NEW version as AWSCURRENT",
        ctx=ctx,
    )
    # The version RotateSecret promoted to AWSCURRENT keeps AWSPENDING until the rotation's
    # finish step clears it, so either stage set is a completed promotion.
    rotated_payload, rotated_from_value = _secret_json(
        sm, secret_arn, expected_stages=(("AWSCURRENT", "AWSPENDING"), ("AWSCURRENT",))
    )
    assert rotated_from_value == rotated_version, (
        f"GetSecretValue must serve the newly staged version {rotated_version!r}, got "
        f"{rotated_from_value!r}"
    )
    assert rotated_payload.get("password") != original_password, (
        f"rotation must produce a DIFFERENT password: AWSCURRENT moved from {original_version!r} "
        f"to {rotated_version!r} but the payload still holds the pre-rotation value, so the new "
        f"version is a copy. (Neither password is quoted here — both are live credentials.)"
    )
    assert rotated_payload.get("username") == MASTER_USERNAME, (
        f"rotation must keep the same admin username: expected {MASTER_USERNAME!r}, got "
        f"{rotated_payload.get('username')!r}"
    )

    # Terminal assertion, back at the producer's own read surface: the rotation happened IN PLACE —
    # same arn, same cluster, and the cluster settles back to `available` after the modification
    # rotating an admin password drives.
    _wait_until(
        lambda: _cluster_status(rs, cluster_id),
        lambda s: s == "available",
        timeout_s=_BACK_TO_AVAILABLE_DEADLINE_S,
        interval_s=2,
        what=f"cluster {cluster_id} to settle back to `available` after the rotation",
        ctx=ctx,
    )
    final = _describe_cluster(rs, cluster_id)
    assert final["MasterPasswordSecretArn"] == secret_arn, (
        f"rotation must not replace the secret, only its contents: expected {secret_arn!r}, got "
        f"{final.get('MasterPasswordSecretArn')!r}"
    )
    assert final["MasterUsername"] == MASTER_USERNAME, (
        f"and the admin username must be untouched: expected {MASTER_USERNAME!r}, got "
        f"{final.get('MasterUsername')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
