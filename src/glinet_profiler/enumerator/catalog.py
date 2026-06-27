"""Curated, risk-classified GL.iNet RPC catalog (seeds the default probe).

Ported from docs/superpowers/specs/2026-06-26-glinet-api-catalog.md.

Tag mapping: R=READ, W=WRITE, D=DANGEROUS, A=ACTIVE.
Edge-case adjustments (integrity rule — READ tags must pass is_read_method):
  - ovpn-server.export_config: doc says R but "export" is in MUTATING_VERBS → W
    (file-generation side effect).
  - logread.export_logs: doc says R but "export" is in MUTATING_VERBS → W
    (file-generation side effect).
"""
# pylint: disable=duplicate-code

from .models import Risk

R, W, D, A = Risk.READ, Risk.WRITE, Risk.DANGEROUS, Risk.ACTIVE

CATALOG: dict[str, dict[str, Risk]] = {
    # ── Core system ────────────────────────────────────────────────────────
    "system": {
        "get_info": R,
        "get_status": R,
        "get_load": R,
        "disk_info": R,
        "get_timezone_config": R,
        "get_unixtime": R,
        "get_httpd_mem_status": R,
        "get_security_policy": R,
        "get_percent": R,
        "set_timezone_config": W,
        "set_security_policy": W,
        "add_user": W,
        "remove_user": W,
        "set_password": D,
        "reset_firmware": D,
        "reboot": D,
    },
    "wifi": {
        "get_config": R,
        "get_status": R,
        "get_mlo_config": R,
        "set_config": W,
        "set_txpower": W,
        "set_mlo_config": W,
    },
    "clients": {
        "get_list": R,
        "get_status": R,
        "block_client": W,
        "remove_offline": W,
        "set_info": W,
        "clear_cache": W,
    },
    "lan": {
        "get_static_bind_list": R,
        "get_config_list": R,
        "set_config": W,
        "add_static_bind": W,
        "set_static_bind": W,
        "remove_static_bind": W,
    },
    "macclone": {
        "get_mac": R,
        "set_mac": W,
    },
    "edgerouter": {
        "get_status": R,
        "status": R,
        "get_config": R,
        "scan": A,
        "set_config": W,
        "set_devices": W,
    },
    # ── Network ────────────────────────────────────────────────────────────
    "network": {
        "get_arp_list": R,
        "get_dhcp_leases": R,
        "check_wan_cable": R,
        "routes": R,
        "routes6": R,
    },
    "cable": {
        "get_status": R,
        "get_config": R,
        "set_config": W,
        "change_interface": W,
    },
    "repeater": {
        "get_config": R,
        "get_status": R,
        "get_saved_ap_list": R,
        "scan": A,
        "connect": W,
        "disconnect": W,
        "set_config": W,
        "forget": W,
        "remove_saved_ap": W,
        "enter_bare_mode": W,
        "exit_bare_mode": W,
    },
    "tethering": {
        "get_status": R,
        "set_connect": W,
        "disconnect": W,
    },
    "modem": {
        "get_info": R,
        "get_status": R,
        "get_config": R,
        "get_cells_info": R,
        "get_sms_list": R,
        "get_traffic_config": R,
        "get_debug_msg": R,
        "set_connect": W,
        "disconnect": W,
        "set_auto_connect": W,
        "send_sms": W,
        "set_sms": W,
        "remove_sms": W,
        "reset_traffic_count": W,
        "set_traffic_auto_save": W,
        "send_at_command": D,
        "reboot_modem": D,
    },
    # ── VPN: WireGuard ─────────────────────────────────────────────────────
    "wg-client": {
        "get_status": R,
        "get_all_config_list": R,
        "get_config_list": R,
        "get_group_list": R,
        "get_setting": R,
        "get_route_list": R,
        "get_recommend_config": R,
        "get_third_config": R,
        "check_config": R,
        "start": W,
        "stop": W,
        "add_config": W,
        "set_config": W,
        "remove_config": W,
        "clear_config_list": W,
        "confirm_config": W,
        "add_group": W,
        "set_group": W,
        "remove_group": W,
        "set_proxy": W,
        "set_setting": W,
        "add_route": W,
        "set_route": W,
        "remove_route": W,
    },
    "wg-server": {
        "get_status": R,
        "get_config": R,
        "get_peer_list": R,
        "get_route_list": R,
        "get_setting": R,
        "start": W,
        "stop": W,
        "set_config": W,
        "set_setting": W,
        "add_peer": W,
        "set_peer": W,
        "remove_peer": W,
        "generate_peer": W,
        "generate_key": W,
        "generate_publickey": W,
        "add_route": W,
        "set_route": W,
        "remove_route": W,
    },
    # ── VPN: OpenVPN ───────────────────────────────────────────────────────
    "ovpn-client": {
        "get_status": R,
        "get_all_config_list": R,
        "get_config_list": R,
        "get_group_list": R,
        "get_setting": R,
        "get_route_list": R,
        "get_recommend_config": R,
        "get_third_config": R,
        "check_config": R,
        "start": W,
        "stop": W,
        "add_config": W,
        "set_config": W,
        "remove_config": W,
        "clear_config_list": W,
        "confirm_config": W,
        "add_group": W,
        "set_group": W,
        "remove_group": W,
        "set_setting": W,
        "add_route": W,
        "set_route": W,
        "remove_route": W,
    },
    "ovpn-server": {
        "get_status": R,
        "get_config": R,
        "get_user_list": R,
        "get_route_list": R,
        "get_setting": R,
        "start": W,
        "stop": W,
        "set_config": W,
        "set_setting": W,
        "generate_certificate": W,
        # doc says R but "export" is in MUTATING_VERBS → downgrade to W
        "export_config": W,
        "add_user": W,
        "remove_user": W,
        "add_route": W,
        "set_route": W,
        "remove_route": W,
    },
    # ── VPN: unified client + policy ───────────────────────────────────────
    "vpn-client": {
        "get_status": R,
        "get_tunnel": R,
        "set_tunnel": W,
    },
    "vpn-policy": {
        "get_global_policy": R,
        "get_proxy_mode": R,
        "get_domain_policy": R,
        "get_mac_policy": R,
        "get_vlan_policy": R,
        "set_global_policy": W,
        "set_proxy_mode": W,
        "set_domain_policy": W,
        "set_mac_policy": W,
        "set_vlan_policy": W,
    },
    # ── Overlay networks ───────────────────────────────────────────────────
    "tailscale": {
        "get_status": R,
        "get_config": R,
        "set_config": W,
    },
    "zerotier": {
        "get_config": R,
        "get_status": R,
        "set_config": W,
    },
    "tor": {
        "get_config": R,
        "get_status": R,
        "set_config": W,
        "replace_country": W,
    },
    # ── Security / access control ──────────────────────────────────────────
    "parental-control": {
        "get_config": R,
        "get_status": R,
        "get_brief": R,
        "get_mode": R,
        "set_config": W,
        "set_brief": W,
        "set_group": W,
        "set_mode": W,
        "update": W,
    },
    "bark": {
        # content filtering — only a write method documented
        "set_config": W,
    },
    "adguardhome": {
        "get_config": R,
        "set_config": W,
    },
    "firewall": {
        "get_zone_list": R,
        "get_rule_list": R,
        "get_dmz": R,
        "get_port_forward_list": R,
        "get_wan_access": R,
        "get_acl_rule_list": R,
        "get_acl_zone_list": R,
        "add_rule": W,
        "set_rule": W,
        "remove_rule": W,
        "set_dmz": W,
        "add_port_forward": W,
        "set_port_forward": W,
        "remove_port_forward": W,
        "set_wan_access": W,
        "add_acl_rule": W,
        "set_acl_rule": W,
        "remove_acl_rule": W,
        "order_rule": W,
        "order_port_forward": W,
    },
    "acl": {
        "get_group_list": R,
        "get_acl_list": R,
        "add_group": W,
        "remove_group": W,
        "add_acl": W,
        "remove_acl": W,
        "add_user": W,
        "remove_user": W,
    },
    "black_white_list": {
        "get_config": R,
        "set_config": W,
        "set_single_mac": W,
    },
    # ── DNS / IP ───────────────────────────────────────────────────────────
    "ddns": {
        "get_config": R,
        "get_status": R,
        "set_config": W,
    },
    "dns": {
        "get_info": R,
        "get_config": R,
        "get_host": R,
        "set_info": W,
        "set_config": W,
        "set_host": W,
    },
    "custom_dns": {
        "get_info": R,
        "set_info": W,
    },
    "ipv6": {
        "get_ipv6": R,
        "set_ipv6": W,
    },
    # ── Network mode / routing ─────────────────────────────────────────────
    "netmode": {
        "get_mode": R,
        "set_mode": W,
    },
    "kmwan": {
        "get_status": R,
        "get_config": R,
    },
    "s2s": {
        "get_status": R,
        "set_config": W,
        "remove_config": W,
        "start_wg": W,
        "stop_wg": W,
        "enable_echo_server": W,
        "generate_wg_genkey": W,
    },
    # ── Traffic / QoS ──────────────────────────────────────────────────────
    "flow_statistics": {
        "get_flow_statistics": R,
        "get_app_flow_statistics": R,
        "get_top_app_flow_statistics": R,
        "get_statistics_rule": R,
        "set_statistics_rule": W,
        "clear_statistics": W,
    },
    "qos": {
        "get_config": R,
        "get_client_list": R,
        "get_device_group": R,
        "enable_qos": W,
        "set_model": W,
        "add_speed_limit_rule": W,
        "set_speed_limit_rule": W,
        "remove_speed_limit_rule": W,
        "add_device_group": W,
        "set_device_group": W,
        "remove_device_group": W,
        "set_channel_bandwidth_ratio": W,
        "set_other_client_priority": W,
    },
    "sqm": {
        "get_config": R,
        "get_status": R,
        "set_config": W,
    },
    # ── System management ──────────────────────────────────────────────────
    "upgrade": {
        "get_config": R,
        "get_online_upgrade_status": R,
        "check_firmware_local": R,
        "check_firmware_online": A,
        "set_config": W,
        "upgrade_online": D,
        "upgrade_local": D,
    },
    "reboot": {  # scheduled-reboot service (distinct from system.reboot)
        "get_config": R,
        "set_config": W,
    },
    "led": {
        "get_config": R,
        "set_config": W,
    },
    "fan": {
        "get_status": R,
        "get_config": R,
        "set_config": W,
        "set_status": W,
    },
    "plugins": {
        "get_repository_status": R,
        "get_list": R,
        "get_package_info": R,
        "update_repository": W,
        "install_package": W,
        "remove_package": W,
    },
    # ── UI / cloud ─────────────────────────────────────────────────────────
    "ui": {
        "get_lang": R,
        "get_menu_list": R,
        "check_initialized": R,
        "load_locales": R,
        "set_lang": W,
        "init": D,
    },
    "cloud": {
        "get_config": R,
        "set_config": W,
        "unbind": W,
    },
    "rtty": {
        "get_config": R,
        "set_config": W,
        "run": W,
        "stop": W,
    },
    # ── Diagnostics / logging ──────────────────────────────────────────────
    "diag": {
        "ping": A,
        "traceroute": A,
    },
    "logread": {
        "get_uboot_log": R,
        "get_system_log": R,
        "get_kernel_log": R,
        "get_crash_log": R,
        "get_config": R,
        # "export_logs" first token "export" is in MUTATING_VERBS → W
        "export_logs": W,
        "remove_crash_log": W,
        "set_config": W,
    },
    # ── NAS (NAS models) ───────────────────────────────────────────────────
    "nas-web": {
        "get_status": R,
        "get_nas_ser": R,
        "get_proto_config": R,
        "get_user_list": R,
        "get_disk_list": R,
        "get_file_list": R,
        "get_share_list": R,
        "set_config": W,
        "add_user": W,
        "remove_user": W,
        "eject_disk": W,
        "start": W,
    },
    "samba": {
        "get_config": R,
        "set_config": W,
    },
    "dlna": {
        "get_config": R,
        "set_config": W,
    },
    # ── Hardware / peripheral ──────────────────────────────────────────────
    "igmp": {
        "get": R,
        "set": W,
    },
    "switch-button": {
        "get_funcs": R,
        "get_config": R,
        "set_config": W,
    },
    "mcu": {
        "get_config": R,
        "get_battery_config": R,
        "set_config": W,
        "set_battery_config": W,
    },
    # ── ★NEW services (SSH ground-truth; methods inferred from patterns) ───
    "dpi": {
        "get_status": R,
        "get_config": R,
        "set_config": W,
    },
    "mptun": {
        "get_status": R,
        "get_config": R,
        "set_config": W,
        "start": W,
        "stop": W,
    },
    "netifyd": {
        "get_config": R,
        "set_config": W,
    },
    "sms-forward": {
        "get_config": R,
        "get_status": R,
        "get_rule_list": R,
        "set_config": W,
        "add_rule": W,
        "remove_rule": W,
    },
    "srv_conn_check": {
        "get_status": R,
        "set_config": W,
    },
    "timer": {
        "get_config": R,
        "get_list": R,
        "set_config": W,
        "add_config": W,
        "remove_config": W,
    },
}

# Read methods tried against every catalog service even if not explicitly listed.
COMMON_READ_METHODS: tuple[str, ...] = (
    "get_status",
    "get_config",
    "get_info",
    "get_list",
)

READ_VERBS: frozenset[str] = frozenset(
    {"get", "list", "check", "status", "info", "dump", "state", "load"}
)
KNOWN_READ_NAMES: frozenset[str] = frozenset({"routes", "routes6"})
MUTATING_VERBS: frozenset[str] = frozenset(
    {
        "set",
        "add",
        "del",
        "delete",
        "remove",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
        "connect",
        "disconnect",
        "up",
        "down",
        "commit",
        "apply",
        "create",
        "update",
        "signal",
        "clear",
        "generate",
        "send",
        "install",
        "reset",
        "block",
        "init",
        "unbind",
        "export",
        "run",
    }
)
DESTRUCTIVE_METHODS: frozenset[str] = frozenset(
    {
        "reboot",
        "reset_firmware",
        "factoryreset",
        "sysupgrade",
        "factory",
        "upgrade_start",
        "upgrade_online",
        "upgrade_local",
        "watchdog",
        "signal",
        "write",
        "exec",
        "remove",
        "commit",
        "apply",
        "password_set",
        "set_password",
        "reboot_modem",
        "send_at_command",
        "init",
        "unbind",
        "generate_certificate",
    }
)


def _first_token(method: str) -> str:
    return method.split("_", 1)[0]


def is_read_method(method: str) -> bool:
    """True iff the method name is a read (no mutation), per name heuristics."""
    if method in DESTRUCTIVE_METHODS:
        return False
    if method in KNOWN_READ_NAMES:
        return True
    tokens = method.split("_")
    if tokens[0] in MUTATING_VERBS or method in MUTATING_VERBS:
        return False
    return any(token in READ_VERBS for token in tokens)


def risk_of(method: str) -> Risk:
    """Heuristic risk for a method discovered outside the catalog."""
    if method in DESTRUCTIVE_METHODS:
        return Risk.DANGEROUS
    if is_read_method(method):
        return Risk.READ
    return Risk.WRITE
