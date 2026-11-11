"""invalid-parameter-cluster-and-account-ops."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-cluster-and-account-ops"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """Malformed parameters to cluster and account-setting operations return
    InvalidParameterException beside a passing positive control of the same shape, and
    rejected writes leave no effect."""
    ecs = ctx.client("ecs")

    # ---- cluster ops: one real cluster is the positive control for all three ----
    cluster_name = ctx.unique_name("sim2real-behav-ecs-invparam-")
    created = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]
    cluster_arn = created["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))
    assert created["clusterName"] == cluster_name, created

    described = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert described and described[0]["clusterArn"] == cluster_arn, (
        f"positive control: DescribeClusters did not find {cluster_name!r}: {described!r}"
    )

    before_arns = set(ecs.list_clusters(maxResults=100)["clusterArns"])
    assert cluster_arn in before_arns, "positive control: ListClusters did not surface it"

    bad_name = "bad cluster name !! not allowed"
    error = _error(lambda: ecs.create_cluster(clusterName=bad_name))
    expected = (
        "InvalidParameterException",
        r"Cluster name must match ^[a-zA-Z0-9\-_]{1,255}$, but was " + bad_name,
    )
    assert error == expected, f"CreateCluster: expected {expected!r}, got {error!r}"
    after_arns = set(ecs.list_clusters(maxResults=100)["clusterArns"])
    # The listing is account-wide, so other runs may add or remove clusters meanwhile: only a
    # cluster under the rejected name is the refused CreateCluster's effect.
    assert after_arns == before_arns or not any(a.endswith("/" + bad_name) for a in after_arns), (
        f"a rejected CreateCluster created a cluster: {before_arns!r} -> {after_arns!r}"
    )

    error = _error(lambda: ecs.describe_clusters(clusters=["x" * 300]))
    expected = ("InvalidParameterException", r"ClusterName must match ^[a-zA-Z0-9\\-_]{1,255}$")
    assert error == expected, f"DescribeClusters: expected {expected!r}, got {error!r}"

    error = _error(lambda: ecs.list_clusters(maxResults=0))
    expected = ("InvalidParameterException", "Max results can not be lesser than 1")
    assert error == expected, f"ListClusters: expected {expected!r}, got {error!r}"

    # ---- account-setting ops: containerInsights is the shared positive-control subject ----
    default_before = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=True
    ).get("settings", [])
    default_before_value = default_before[0]["value"] if default_before else "disabled"
    default_flip = "disabled" if default_before_value != "disabled" else "enabled"
    ctx.on_cleanup(
        lambda: ecs.put_account_setting_default(name="containerInsights", value=default_before_value)
    )

    put_default = ecs.put_account_setting_default(name="containerInsights", value=default_flip)[
        "setting"
    ]
    assert put_default["value"] == default_flip, (
        f"positive control: PutAccountSettingDefault did not persist {default_flip!r}: {put_default!r}"
    )
    after_default = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=True
    )["settings"]
    assert after_default and after_default[0]["value"] == default_flip, after_default

    error = _error(
        lambda: ecs.put_account_setting_default(name="containerInsights", value="not-a-real-value")
    )
    expected = ("InvalidParameterException", "Invalid setting 'value'")
    assert error == expected, f"PutAccountSettingDefault: expected {expected!r}, got {error!r}"
    still_default = ecs.list_account_settings(
        name="containerInsights", effectiveSettings=True
    )["settings"]
    assert still_default and still_default[0]["value"] == default_flip, (
        f"a rejected PutAccountSettingDefault changed the default: {still_default!r}"
    )

    def _delete_setting_quiet():
        try:
            ecs.delete_account_setting(name="containerInsights", principalArn=principal_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterException":
                raise

    put = ecs.put_account_setting(name="containerInsights", value="enabled")["setting"]
    principal_arn = put["principalArn"]
    ctx.on_cleanup(_delete_setting_quiet)
    assert put["value"] == "enabled", (
        f"positive control: PutAccountSetting did not persist 'enabled': {put!r}"
    )

    scoped = ecs.list_account_settings(name="containerInsights", principalArn=principal_arn)[
        "settings"
    ]
    assert scoped and scoped[0]["value"] == "enabled", scoped

    error = _error(
        lambda: ecs.put_account_setting(name="containerInsights", value="not-a-real-value")
    )
    expected = ("InvalidParameterException", "Invalid setting 'value'")
    assert error == expected, f"PutAccountSetting: expected {expected!r}, got {error!r}"
    still_scoped = ecs.list_account_settings(name="containerInsights", principalArn=principal_arn)[
        "settings"
    ]
    assert still_scoped and still_scoped[0]["value"] == "enabled", (
        f"a rejected PutAccountSetting changed the per-principal value: {still_scoped!r}"
    )

    # `value` without `name` is explicitly documented as invalid.
    error = _error(lambda: ecs.list_account_settings(value="enabled"))
    expected = ("InvalidParameterException", "Setting 'name' must be provided when 'value' is present")
    assert error == expected, f"ListAccountSettings: expected {expected!r}, got {error!r}"

    error = _error(
        lambda: ecs.delete_account_setting(name="containerInsights", principalArn="not-an-arn")
    )
    expected = ("InvalidParameterException", "Invalid PrincipalArn: not-an-arn")
    assert error == expected, f"DeleteAccountSetting: expected {expected!r}, got {error!r}"
    still_present = ecs.list_account_settings(name="containerInsights", principalArn=principal_arn)[
        "settings"
    ]
    assert still_present and still_present[0]["value"] == "enabled", (
        "a rejected DeleteAccountSetting removed the per-principal setting anyway"
    )

    # Positive control: the identical shape with a real ARN actually deletes it.
    ecs.delete_account_setting(name="containerInsights", principalArn=principal_arn)
    gone = ecs.list_account_settings(
        name="containerInsights", principalArn=principal_arn, effectiveSettings=False
    )["settings"]
    assert not any(s.get("principalArn") == principal_arn for s in gone), (
        f"DeleteAccountSetting succeeded but the setting is still listed: {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
