"""Map RPC (service, method) pairs to the GLinet method that wraps them."""

GLI4PY_COVERAGE: dict[tuple[str, str], str] = {
    ("system", "get_info"): "router_info",
    ("system", "get_status"): "router_get_status",
    ("system", "get_load"): "router_get_load",
    ("system", "reboot"): "router_reboot",
    ("macclone", "get_mac"): "router_mac",
    ("edgerouter", "get_status"): "connected_to_internet",
    ("clients", "get_list"): "list_all_clients",
    ("lan", "get_static_bind_list"): "list_static_clients",
    ("wifi", "get_config"): "wifi_ifaces_get",
    ("wifi", "set_config"): "wifi_iface_set_enabled",
    ("diag", "ping"): "ping",
    ("wg-client", "get_all_config_list"): "wireguard_client_list",
    ("wg-client", "get_status"): "wireguard_client_state",
    ("wg-client", "start"): "wireguard_client_start",
    ("wg-client", "stop"): "wireguard_client_stop",
    ("vpn-client", "get_status"): "wireguard_client_state",
    ("vpn-client", "set_tunnel"): "wireguard_client_start",
    ("tailscale", "get_status"): "tailscale_connection_state",
    ("tailscale", "get_config"): "tailscale_configured",
    ("tailscale", "set_config"): "tailscale_start",
}


def covered_by(service: str, method: str) -> str | None:
    """Return the GLinet method wrapping (service, method), or None."""
    return GLI4PY_COVERAGE.get((service, method))
