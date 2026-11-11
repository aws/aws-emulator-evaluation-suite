"""secure-string-customer-managed-kms-key-overwrite-rekeys-history."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "secure-string-customer-managed-kms-key-overwrite-rekeys-history"
GROUP = 'state-machine'
SERVICES = ['ssm']


def _create_cmk(ctx, kms, suffix):
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-ssmkey-" + suffix + "-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Overwriting a SecureString with a new KMS key re-keys only the new version; history keeps
    each version's key, an omitted KeyId reuses the last key, and the KeyId filter matches
    only the current key by bare id.
    """
    ssm = ctx.client("ssm")
    kms = ctx.client("kms")
    base = "/" + ctx.unique_name("sim2real-behav-cmk-")
    name = f"{base}/secret"

    key1 = _create_cmk(ctx, kms, "k1")
    key2 = _create_cmk(ctx, kms, "k2")

    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    put1 = ssm.put_parameter(Name=name, Value="plaintext-v1", Type="SecureString", KeyId=key1)
    assert put1["Version"] == 1, f"first PutParameter must mint version 1, got {put1!r}"

    def _current_key_id():
        page = ssm.describe_parameters(
            ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
        )["Parameters"]
        assert len(page) == 1, page
        return page[0]["KeyId"]

    assert _current_key_id() == key1, (
        f"DescribeParameters must report the bare KeyId {key1!r} the parameter was just "
        f"written with, got {_current_key_id()!r}"
    )
    decrypted1 = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    assert decrypted1 == "plaintext-v1", (
        f"GetParameter must decrypt version 1 under key1 back to its plaintext, got {decrypted1!r}"
    )

    put2 = ssm.put_parameter(
        Name=name, Value="plaintext-v2", Type="SecureString", KeyId=key2, Overwrite=True
    )
    assert put2["Version"] == 2, f"the overwrite must mint version 2, got {put2!r}"
    assert _current_key_id() == key2, (
        f"after overwriting with key2, DescribeParameters must report {key2!r} as the "
        f"CURRENT key -- the parameter re-keys on overwrite, got {_current_key_id()!r}"
    )
    decrypted2 = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    assert decrypted2 == "plaintext-v2", (
        f"GetParameter must now decrypt version 2 under key2, got {decrypted2!r}"
    )

    # History: each version keeps the key it was written under, and each still decrypts
    # correctly under ITS OWN key, not the current one.
    history = ssm.get_parameter_history(Name=name, WithDecryption=True)["Parameters"]
    by_version = {h["Version"]: h for h in history}
    assert set(by_version) == {1, 2}, f"expected versions 1 and 2 in history, got {sorted(by_version)}"
    assert by_version[1]["KeyId"] == key1, (
        f"version 1's history entry must still report key1 {key1!r}, got {by_version[1]['KeyId']!r}"
    )
    assert by_version[1]["Value"] == "plaintext-v1", (
        f"version 1's history entry must still decrypt to its own plaintext under key1, "
        f"got {by_version[1]['Value']!r}"
    )
    assert by_version[2]["KeyId"] == key2, (
        f"version 2's history entry must report key2 {key2!r}, got {by_version[2]['KeyId']!r}"
    )
    assert by_version[2]["Value"] == "plaintext-v2", (
        f"version 2's history entry must decrypt to its own plaintext under key2, got "
        f"{by_version[2]['Value']!r}"
    )

    # Overwriting again WITHOUT a KeyId keeps the LAST key used (key2) -- it does not
    # revert to the account's default alias/aws/ssm key.
    put3 = ssm.put_parameter(Name=name, Value="plaintext-v3", Type="SecureString", Overwrite=True)
    assert put3["Version"] == 3, f"the third write must mint version 3, got {put3!r}"
    assert _current_key_id() == key2, (
        f"omitting KeyId on overwrite must keep reusing the previous key {key2!r}, not "
        f"revert to a default key; DescribeParameters reported {_current_key_id()!r}"
    )
    decrypted3 = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    assert decrypted3 == "plaintext-v3", decrypted3

    # The KeyId filter on both read surfaces matches the CURRENT key by its bare id, not
    # by a stale key this parameter used to carry, and not by the key's ARN.
    key2_arn = kms.describe_key(KeyId=key2)["KeyMetadata"]["Arn"]

    described_current = ssm.describe_parameters(
        ParameterFilters=[
            {"Key": "Name", "Option": "Equals", "Values": [name]},
            {"Key": "KeyId", "Option": "Equals", "Values": [key2]},
        ]
    )["Parameters"]
    assert [p["Name"] for p in described_current] == [name], (
        f"DescribeParameters KeyId=Equals[{key2!r}] (current, bare id) must find the "
        f"parameter, got {[p['Name'] for p in described_current]}"
    )

    described_stale = ssm.describe_parameters(
        ParameterFilters=[
            {"Key": "Name", "Option": "Equals", "Values": [name]},
            {"Key": "KeyId", "Option": "Equals", "Values": [key1]},
        ]
    )["Parameters"]
    assert described_stale == [], (
        f"DescribeParameters KeyId=Equals[{key1!r}] (the STALE, superseded key) must not "
        f"find the parameter -- the filter tracks only the current version's key, got "
        f"{[p['Name'] for p in described_stale]}"
    )

    by_path_current = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "KeyId", "Option": "Equals", "Values": [key2]}],
    )["Parameters"]
    assert [p["Name"] for p in by_path_current] == [name], (
        f"GetParametersByPath KeyId=Equals[{key2!r}] must find the parameter under the "
        f"current key, got {[p['Name'] for p in by_path_current]}"
    )

    by_path_arn = ssm.get_parameters_by_path(
        Path=base, Recursive=True,
        ParameterFilters=[{"Key": "KeyId", "Option": "Equals", "Values": [key2_arn]}],
    )["Parameters"]
    assert by_path_arn == [], (
        f"GetParametersByPath KeyId=Equals[{key2_arn!r}] (the key's ARN, not its bare id) "
        f"must NOT match -- the filter compares against the bare key id as stored, got "
        f"{[p['Name'] for p in by_path_arn]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
