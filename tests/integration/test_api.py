"""Integration tests for FastAPI endpoints and security middleware."""

import pytest
from fastapi.testclient import TestClient

from fwmanager.api.app import app
from fwmanager.api.routes import driver, safety_switch
from fwmanager.models.rules import FirewallPolicy

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_api_state() -> None:
    """Ensure clean state before each test."""
    safety_switch.confirm()
    driver.active_policy = FirewallPolicy(name="clean_test_policy")


def test_health_endpoint() -> None:
    """Test /health returns ok and checks security headers."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert data["backend"] == "simulation"

    # Security headers verification
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


def test_rules_crud_workflow() -> None:
    """Test getting, adding, and deleting firewall rules."""
    # List initial rules
    r_list = client.get("/api/v1/rules")
    assert r_list.status_code == 200
    assert r_list.json()["policy_name"] == "clean_test_policy"

    # Add rule
    payload = {
        "chain": "INPUT",
        "protocol": "tcp",
        "port": "443",
        "source_ip": "10.0.0.0/24",
        "action": "ACCEPT",
        "comment": "HTTPS ingress",
    }
    r_add = client.post("/api/v1/rules", json=payload)
    assert r_add.status_code == 201
    added_data = r_add.json()
    rule_id = added_data["id"]
    assert added_data["port"] == "443"

    # Verify rule is listed
    r_list_after = client.get("/api/v1/rules")
    assert len(r_list_after.json()["rules"]) == 1

    # Delete rule
    r_del = client.delete(f"/api/v1/rules/{rule_id}")
    assert r_del.status_code == 200
    assert "deleted successfully" in r_del.json()["message"]

    # Delete non-existent
    r_del_404 = client.delete(f"/api/v1/rules/{rule_id}")
    assert r_del_404.status_code == 404


def test_add_rule_invalid_port() -> None:
    """Test validation failure for out-of-bounds port."""
    payload = {
        "chain": "INPUT",
        "protocol": "tcp",
        "port": "99999",
        "action": "ACCEPT",
    }
    resp = client.post("/api/v1/rules", json=payload)
    assert resp.status_code == 422


def test_profiles_and_deadman_switch() -> None:
    """Test listing profiles, applying profile, confirming, and manual rollback."""
    # List profiles
    r_prof = client.get("/api/v1/profiles")
    assert r_prof.status_code == 200
    assert "hardened_server" in r_prof.json()

    # Apply unknown profile
    r_unknown = client.post(
        "/api/v1/profiles/apply",
        json={"profile_name": "unknown_profile_abc", "timeout_seconds": 10},
    )
    assert r_unknown.status_code == 404

    # Apply valid profile
    r_apply = client.post(
        "/api/v1/profiles/apply",
        json={"profile_name": "hardened_server", "timeout_seconds": 30},
    )
    assert r_apply.status_code == 200
    apply_data = r_apply.json()
    assert apply_data["armed"] is True

    # Check status endpoint
    r_stat = client.get("/api/v1/safety/status")
    assert r_stat.status_code == 200
    assert r_stat.json()["armed"] is True

    # Confirm policy
    r_conf = client.post("/api/v1/safety/confirm")
    assert r_conf.status_code == 200
    assert r_conf.json()["status"] == "confirmed"

    # Confirming again raises 400
    r_conf_again = client.post("/api/v1/safety/confirm")
    assert r_conf_again.status_code == 400


def test_safety_manual_rollback() -> None:
    """Test manual rollback endpoint."""
    client.post(
        "/api/v1/profiles/apply",
        json={"profile_name": "workstation", "timeout_seconds": 20},
    )

    r_rb = client.post("/api/v1/safety/rollback")
    assert r_rb.status_code == 200
    assert r_rb.json()["status"] == "rolled_back"

    # Rollback again raises 400
    r_rb_again = client.post("/api/v1/safety/rollback")
    assert r_rb_again.status_code == 400


def test_export_endpoint_formats() -> None:
    """Test export endpoint for json, cef, nft, and ipt."""
    for fmt in ("json", "cef", "nft", "ipt"):
        resp = client.get(f"/api/v1/export?format={fmt}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == fmt
        assert len(data["output"]) > 0

    # Bad format fails query validation
    bad_resp = client.get("/api/v1/export?format=unknown_format")
    assert bad_resp.status_code == 422
