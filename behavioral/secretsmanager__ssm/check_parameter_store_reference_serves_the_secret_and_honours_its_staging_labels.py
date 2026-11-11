"""parameter-store-reference-serves-the-secret-and-honours-its-staging-labels."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# The reference parameter is virtual: nothing in Parameter Store needs deleting.

CHECK = "parameter-store-reference-serves-the-secret-and-honours-its-staging-labels"
GROUP = "cross-service"
SERVICES = ["secretsmanager", "ssm"]

_PREFIX = "/aws/reference/secretsmanager"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A secret reads through /aws/reference/secretsmanager as SecureString, `:<STAGE>` selects by
    staging label, a missing label does not fall back, and the path is not enumerable by path.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html
    """
    sm = ctx.client("secretsmanager")
    ssm = ctx.client("ssm")

    name = ctx.unique_name("sim2real-behav-smssmref-")
    created = sm.create_secret(
        Name=name,
        SecretString=json.dumps({"username": "app", "password": "current-pw"}),
        Description="sim2real behavioral draft: Parameter Store reference to a secret",
        Tags=_sim2real_tags(),
    )
    arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    v2 = sm.put_secret_value(
        SecretId=arn, SecretString=json.dumps({"username": "app", "password": "rotated-pw"})
    )["VersionId"]
    assert v2 != v1, f"PutSecretValue must mint a new version id; got {v2!r} == {v1!r}"

    # Expected values below are derived from the producer's own reads, never from literals.
    _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: v1 in m and v2 in m and "AWSCURRENT" not in m.get(v1, []),
        timeout_s=60.0,
        interval_s=2.0,
        description="the staging index to stop reporting v1 as AWSCURRENT",
    )
    current = sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    previous = sm.get_secret_value(SecretId=arn, VersionStage="AWSPREVIOUS")
    assert current["VersionId"] == v2 and previous["VersionId"] == v1, (
        f"the producer must report v2 as AWSCURRENT and v1 as AWSPREVIOUS before the consumer is "
        f"graded; got current={current['VersionId']!r} previous={previous['VersionId']!r}"
    )
    assert current["SecretString"] != previous["SecretString"], (
        "the two staging labels must serve DIFFERENT bytes, or the label-selection assertion below "
        "could not fail"
    )

    ref = f"{_PREFIX}/{name}"

    resolved = _poll(
        lambda: _get_parameter(ssm, ref, decrypt=True),
        lambda r: r[0] == "OK",
        timeout_s=90.0,
        interval_s=3.0,
        description=(
            f"the Parameter Store reference {ref!r} to become resolvable (the front door is a "
            f"different service from the store and may lag CreateSecret)"
        ),
    )
    param = resolved[1]
    assert param["Value"] == current["SecretString"], (
        f"GetParameter on {ref!r} must serve the AWSCURRENT SecretString byte-for-byte; Secrets "
        f"Manager reports {current['SecretString']!r}, SSM returned {param.get('Value')!r}"
    )
    assert param["Type"] == "SecureString", (
        f"a Secrets Manager reference must be presented as SecureString; "
        f"GetParameter reported Type={param.get('Type')!r}"
    )
    assert param["Name"] == ref, (
        f"the echoed parameter name must be the reference path; expected {ref!r}, got "
        f"{param.get('Name')!r}"
    )
    # SSM must have resolved the version the producer independently reports as AWSCURRENT.
    source = _source_version_id(param)
    assert source == v2, (
        f"the reference read must resolve the version Secrets Manager reports as AWSCURRENT; the "
        f"producer says {v2!r}, SourceResult carries {source!r} (raw "
        f"{param.get('SourceResult')!r})"
    )

    # The :<STAGE> selector resolves by staging label, not by parameter version.
    labelled = _get_parameter(ssm, f"{ref}:AWSPREVIOUS", decrypt=True)
    assert labelled[0] == "OK", (
        f"the reference must accept a staging-label selector; GetParameter on "
        f"{ref + ':AWSPREVIOUS'!r} returned {labelled[0]!r}"
    )
    labelled_param = labelled[1]
    assert labelled_param["Value"] == previous["SecretString"], (
        f"the :AWSPREVIOUS selector must serve the DEMOTED version's bytes, not AWSCURRENT's; "
        f"Secrets Manager reports {previous['SecretString']!r} for AWSPREVIOUS and "
        f"{current['SecretString']!r} for AWSCURRENT, SSM returned {labelled_param.get('Value')!r}"
    )
    labelled_source = _source_version_id(labelled_param)
    assert labelled_source == v1, (
        f"the :AWSPREVIOUS read must resolve v1 ({v1}); SourceResult carries {labelled_source!r}"
    )
    assert labelled_param.get("Selector") == ":AWSPREVIOUS", (
        f"the echoed Selector must be the staging label the caller asked for; got "
        f"{labelled_param.get('Selector')!r}"
    )

    missing = _get_parameter(ssm, f"{ref}:SIM2REALNOSUCHSTAGE", decrypt=True)
    assert missing[0] != "OK", (
        f"a nonexistent staging label must not resolve; GetParameter returned "
        f"{(missing[1] or {}).get('Value')!r} -- a silent fall-back to AWSCURRENT is the single most "
        f"dangerous divergence on this path"
    )

    # Refused or opaque are both acceptable; only the plaintext coming back is wrong.
    undecrypted = _get_parameter(ssm, ref, decrypt=False)
    undecrypted_value = None if undecrypted[1] is None else undecrypted[1].get("Value")
    assert undecrypted_value != current["SecretString"], (
        f"a reference read with WithDecryption=False must not hand back the plaintext secret; it "
        f"returned {undecrypted_value!r} (outcome {undecrypted[0]!r})"
    )

    # The working GetParameter above is the positive control for this absence.
    enumerated, enum_error = _paths_under(ssm, _PREFIX)
    assert not [p for p in enumerated if p == ref], (
        f"GetParametersByPath is documented as unsupported for Secrets Manager references, so "
        f"{ref!r} must not be enumerated; the call returned {enumerated!r} (error {enum_error!r}) "
        f"while GetParameter on the same path succeeds"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _get_parameter(ssm, name: str, *, decrypt: bool):
    """Return (code or 'OK', Parameter or None)."""
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=decrypt)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None
    return "OK", resp["Parameter"]


def _source_version_id(param: dict):
    """Return the Secrets Manager VersionId SSM resolved, from SourceResult; raises if absent."""
    raw = param.get("SourceResult")
    assert raw, (
        f"a Secrets Manager reference read must carry SourceResult (the raw source response); the "
        f"Parameter was {param!r}"
    )
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise AssertionError(
            f"SourceResult must be the source service's JSON response; could not parse {raw!r}"
        ) from exc
    # SourceResult is the raw source response, so its keys are lower-camelCase (versionId),
    # not the PascalCase shape botocore returns from a direct GetSecretValue.
    version_id = parsed.get("versionId")
    assert version_id, (
        f"SourceResult must name the resolved Secrets Manager versionId; parsed keys were "
        f"{sorted(parsed)!r}"
    )
    return version_id


def _paths_under(ssm, path: str):
    """Return (names, error code or None) for a recursive GetParametersByPath.

    The docs do not say whether an unsupported path raises or returns nothing, so both are captured.
    """
    names = []
    token = None
    while True:
        kw = {"Path": path, "Recursive": True, "WithDecryption": True, "MaxResults": 10}
        if token is not None:
            kw["NextToken"] = token
        try:
            page = ssm.get_parameters_by_path(**kw)
        except ClientError as exc:
            return names, exc.response.get("Error", {}).get("Code")
        for row in page.get("Parameters", []):
            names.append(row.get("Name"))
        token = page.get("NextToken")
        if not token:
            return names, None


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
