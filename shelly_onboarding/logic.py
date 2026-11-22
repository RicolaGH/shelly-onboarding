import copy
import ipaddress
from device_migrator.universal import build_discovery
import re


# Fields writable via SetConfig that do not carry the source device's identity
# or connection profile. Protection limits are only portable within a model.
TEMPLATE_FIELDS = {
    "switch:0": ("Switch", (
        "in_mode", "in_locked", "auto_on", "auto_on_delay", "auto_off", "auto_off_delay",
        "power_restore_delay_enable", "power_restore_delay", "autorecover_voltage_errors",
        "power_limit", "voltage_limit", "undervoltage_limit", "current_limit", "counts",
    )),
    "sys": ("Sys", ("device.eco_mode", "device.discoverable", "location.tz", "location.lat", "location.lon", "sntp.server")),
    "ble": ("BLE", ("enable", "rpc.enable", "observer.enable")),
    "cloud": ("Cloud", ("enable",)),
    "matter": ("Matter", ("enable",)),
}
SWITCH_PROTECTION = {"power_limit", "voltage_limit", "undervoltage_limit", "current_limit", "autorecover_voltage_errors"}
PLUG_UI = re.compile(r"plug[a-z0-9]*_ui", re.I)


def select_settings(config, paths):
    selected = {}
    for path in paths:
        parent, _, child = path.partition(".")
        if not child:
            if parent in config:
                selected[parent] = config[parent]
        elif isinstance(config.get(parent), dict) and child in config[parent]:
            selected.setdefault(parent, {})[child] = config[parent][child]
    return selected


def setting_values(config, prefix):
    values = {}
    for key, value in config.items():
        path = f"{prefix}.{key}"
        if isinstance(value, dict) and value:
            values.update(setting_values(value, path))
        else:
            values[path] = value
    return values


def template_settings(config):
    settings = {}
    for key, values in config.items():
        if not isinstance(values, dict):
            continue
        if PLUG_UI.fullmatch(key):
            method, fields = key.upper(), ("leds.mode", "leds.colors", "leds.night_mode", "controls")
        elif key in TEMPLATE_FIELDS:
            method, fields = TEMPLATE_FIELDS[key]
        else:
            continue
        if selected := select_settings(values, fields):
            settings[key] = {"method": method, "config": selected}
    planned = {path for key, entry in settings.items() for path in setting_values(entry["config"], key)}
    planned.update({"switch:0.initial_state", "wifi.sta.ssid", "mqtt.server", "mqtt.user", "mqtt.ssl_ca"})
    skipped = []
    for key, value in config.items():
        if isinstance(value, dict) and (key in settings or key in TEMPLATE_FIELDS or key in ("wifi", "mqtt")):
            skipped.extend(path for path in setting_values(value, key) if path not in planned)
        else:
            skipped.append(key)
    return settings, sorted(skipped)


def compatible_settings(source, target):
    """Select source values whose keys are also supported by the target."""
    matched = {}
    for key in source.keys() & target.keys():
        value = source[key]
        if isinstance(value, dict):
            if isinstance(target[key], dict) and (nested := compatible_settings(value, target[key])):
                matched[key] = nested
        else:
            matched[key] = value
    return matched


def local_ip(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in ipaddress.ip_network(net) for net in ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12")):
        raise ValueError("Private IPv4-Adresse erforderlich.")
    return str(address)


def plug(info):
    if info.get("gen") not in (2, 3, 4) or "plug" not in info.get("app", "").lower():
        raise ValueError("v0.1 unterstützt RPC-WLAN-Plugs der Generationen 2–4.")
    if not re.fullmatch(r"[0-9a-fA-F]{12}", info.get("mac", "")):
        raise ValueError("Ungültige Geräte-MAC.")
    return info["mac"].lower()


def radio(network, interface):
    devices = network["interfaces"]
    wlan = next((d for d in devices if d["interface"] == interface), {})
    if wlan.get("type") != "wireless" or not any(d.get("type") == "ethernet" and d.get("primary") and d.get("connected") for d in devices):
        raise ValueError("Werks-WLAN benötigt primäres Ethernet und einen separaten WLAN-Adapter.")
    if wlan.get("primary") or wlan.get("connected") or (wlan.get("wifi") or {}).get("ssid"):
        raise ValueError("Der WLAN-Adapter muss frei und ohne gespeichertes WLAN sein.")
    factory = ipaddress.ip_network("192.168.33.0/24")
    for d in devices:
        for addr in (d.get("ipv4") or {}).get("address", []):
            if ipaddress.ip_interface(addr).network.overlaps(factory):
                raise ValueError("192.168.33.0/24 überschneidet sich mit einer Hostroute.")
    return wlan


def discovery(info, plan, prefix, config, ip):
    plug(info)
    data = {"id":info["id"], "device_config":config}
    messages = build_discovery("gen2", plan["topic"], data, ip, plan["name"])["messages"]
    switches = [m for m in messages if m["topic"].startswith("homeassistant/switch/")
                and m["payload"].get("stat_t") == "~status/switch:0"]
    if len(switches) != 1:
        raise ValueError("Discovery erwartet einen unterstützten Plug mit einem Schaltausgang.")
    for message in messages:
        message["topic"] = prefix + "/" + message["topic"].split("/",1)[1]
    return messages, switches[0]["payload"]["unique_id"]


def extend(config, old, new):
    result = copy.deepcopy(config)
    changes = []
    def visit(node, path):
        if isinstance(node, list):
            for i, child in enumerate(node):
                visit(child, f"{path}/{i}")
        if not isinstance(node, dict):
            return
        service = node.get("action", node.get("service"))
        target = node.get("target")
        if service in ("switch.turn_on", "switch.turn_off", "homeassistant.turn_on", "homeassistant.turn_off") and isinstance(target, dict):
            ids = target.get("entity_id", [])
            ids = [ids] if isinstance(ids, str) else ids
            if isinstance(ids, list) and old in ids and new not in ids:
                target["entity_id"] = [*ids, new]
                changes.append(path + "/target/entity_id")
        for key in ("action", "actions", "sequence", "then", "else", "choose", "default", "parallel", "repeat"):
            if key in node:
                visit(node[key], f"{path}/{key}")
    visit(result, "")
    return result, changes


def plan_fields(data):
    p = {key: str(data.get(key, "")).strip() for key in ("name", "ssid", "broker", "user", "tls", "topic", "initial_state", "area")}
    if not p["name"] or len(p["name"]) > 64 or not 1 <= len(p["ssid"].encode()) <= 32:
        raise ValueError("Gerätename und gültige SSID erforderlich.")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+:[0-9]{1,5}", p["broker"]) or not 0 < int(p["broker"].split(":")[1]) < 65536:
        raise ValueError("Broker als DNS-Name:Port angeben.")
    if not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", p["topic"]):
        raise ValueError("Ungültiges MQTT-Topic.")
    if p["tls"] not in ("off", "user_ca.pem", "ca.pem") or p["initial_state"] not in ("on", "off", "restore_last"):
        raise ValueError("Ungültige TLS- oder Einschaltoption.")
    return p
