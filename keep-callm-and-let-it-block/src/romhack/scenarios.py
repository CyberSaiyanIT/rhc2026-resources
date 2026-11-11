"""Controlled client identities and repeatable workshop request sequences."""

VPN_IP = "198.51.100.40"
# Display names follow the Dragon Ball theme; role keeps the teaching meaning visible.
CLIENTS = {
    "198.51.100.10": {"name": "Frieza", "role": "Scanner", "attacker": True},
    "198.51.100.20": {"name": "Namek citizen", "role": "Shared NAT", "attacker": False},
    "198.51.100.30": {"name": "Bulma", "role": "Benign browser", "attacker": False},
    VPN_IP: {"name": "Piccolo", "role": "VPN", "attacker": False},
}
SCENARIO_IPS = tuple(CLIENTS)


def active_ips(phase):
    return SCENARIO_IPS if phase in ("C1", "C2", "C3") else SCENARIO_IPS[:3]


def requests(phase):
    original = (
        [("198.51.100.10", "PROPFIND", f"/missing/admin-{i}", {}) for i in range(16)]
        + [("198.51.100.20", "GET", "/login" if i < 10 else "/", {}) for i in range(16)]
        + [("198.51.100.30", "GET", "/", {}) for _ in range(12)]
    )
    if VPN_IP not in active_ips(phase):
        return original
    # Headers survive both the local proxy and hosted path. They represent
    # synthetic identities, never real credentials or an evaluator verdict.
    context = {"X-Romhack-User": "employee-01", "X-Romhack-Session": "vpn-session-01"}
    vpn = [(VPN_IP, "GET", path, context) for path in ["/login"] * 5 + ["/session/login", "/app/home", "/app/orders"]]
    return vpn + original
