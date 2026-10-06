"""Integration tests for Typer and Rich CLI."""

from typer.testing import CliRunner

from fwmanager.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Test 'fw-manager version' command."""
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "Linux Firewall Manager" in res.stdout


def test_cli_rules_workflow() -> None:
    """Test rules list, add, and delete workflow."""
    # List initial
    res_list = runner.invoke(app, ["rules", "list"])
    assert res_list.exit_code == 0

    # Add rule
    res_add = runner.invoke(
        app,
        [
            "rules",
            "add",
            "--chain",
            "INPUT",
            "--protocol",
            "tcp",
            "--port",
            "80",
            "--action",
            "ACCEPT",
        ],
    )
    assert res_add.exit_code == 0
    assert "Added rule" in res_add.stdout

    # List with JSON
    res_json = runner.invoke(app, ["rules", "list", "--json"])
    assert res_json.exit_code == 0
    assert '"port": "80"' in res_json.stdout

    # Add invalid rule
    res_bad = runner.invoke(app, ["rules", "add", "--chain", "INPUT", "--port", "999999"])
    assert res_bad.exit_code == 1


def test_cli_profiles_workflow() -> None:
    """Test profiles list, apply, confirm, and rollback."""
    res_list = runner.invoke(app, ["profiles", "list"])
    assert res_list.exit_code == 0
    assert "hardened_server" in res_list.stdout

    # Apply profile
    res_apply = runner.invoke(app, ["profiles", "apply", "hardened_server", "--timeout", "10"])
    assert res_apply.exit_code == 0
    assert "Applied Profile 'hardened_server'" in res_apply.stdout

    # Check status
    res_stat = runner.invoke(app, ["status"])
    assert res_stat.exit_code == 0
    assert "hardened_server" in res_stat.stdout

    # Confirm
    res_confirm = runner.invoke(app, ["confirm"])
    assert res_confirm.exit_code == 0
    assert "confirmed" in res_confirm.stdout


def test_cli_export_formats() -> None:
    """Test export command in json, cef, nft, and ipt modes."""
    for fmt in ("json", "cef", "nft", "ipt"):
        res = runner.invoke(app, ["export", "--format", fmt])
        assert res.exit_code == 0
        assert len(res.stdout) > 0


def test_cli_rules_delete_and_not_found() -> None:
    """Test deleting rules by ID and handling not found."""
    # Add a rule to delete
    runner.invoke(
        app,
        [
            "rules",
            "add",
            "--chain",
            "INPUT",
            "--protocol",
            "tcp",
            "--port",
            "8080",
            "--action",
            "ACCEPT",
        ],
    )
    # List to get the ID
    res_list = runner.invoke(app, ["rules", "list", "--json"])
    import json

    data = json.loads(res_list.stdout)
    assert len(data["rules"]) > 0
    rule_id = data["rules"][-1]["id"]

    # Delete existing
    res_del = runner.invoke(app, ["rules", "delete", rule_id])
    assert res_del.exit_code == 0
    assert "Deleted rule" in res_del.stdout

    # Delete non-existent
    res_del_missing = runner.invoke(app, ["rules", "delete", "non-existent-id-999"])
    assert res_del_missing.exit_code == 1
    assert "not found" in res_del_missing.stdout


def test_cli_confirm_and_rollback_idle() -> None:
    """Test confirm and rollback when no staged policy exists."""
    # When no switch is armed
    res_conf = runner.invoke(app, ["confirm"])
    assert res_conf.exit_code == 0

    res_rb = runner.invoke(app, ["rollback"])
    assert res_rb.exit_code == 0


def test_cli_profiles_apply_and_rollback() -> None:
    """Test applying a profile and triggering manual rollback."""
    res_apply = runner.invoke(app, ["profiles", "apply", "workstation", "--timeout", "15"])
    assert res_apply.exit_code == 0
    assert "Applied Profile" in res_apply.stdout

    # Now rollback
    res_rb = runner.invoke(app, ["rollback"])
    assert res_rb.exit_code == 0
    assert "Rollback completed" in res_rb.stdout


def test_cli_profiles_unknown() -> None:
    """Test applying an unknown profile."""
    res = runner.invoke(app, ["profiles", "apply", "unknown_profile_xyz"])
    assert res.exit_code == 1
    assert "Unknown profile" in res.stdout
