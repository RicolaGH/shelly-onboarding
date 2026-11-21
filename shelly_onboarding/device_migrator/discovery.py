"""Build Shelly Dimmer 1/2 (Gen1) MQTT Discovery, without touching hardware."""
import hashlib
import ipaddress

def dimmer_discovery(prefix, ip, name="Shelly MQTT Dimmer"):
    if not isinstance(prefix,str) or not prefix or len(prefix)>200 or any(c in prefix for c in '#+\x00\n\r') or prefix.endswith('/'):
        raise ValueError("Vollständigen tatsächlichen MQTT-Prefix ohne Wildcards/abschließenden Slash angeben.")
    ipaddress.ip_address(ip)
    identifier = "dm_" + hashlib.sha256(prefix.encode()).hexdigest()[:20]
    device = {"identifiers":[identifier],"name":name,"manufacturer":"Shelly","model":"Shelly Dimmer 1/2 (Gen1)","configuration_url":f"http://{ip}/"}
    common = {"device":device,"availability_topic":prefix+"/online","payload_available":"true","payload_not_available":"false"}
    # Template schema uses the HA 0..255 scale: explicitly convert to 1..100.
    transition = '{% if transition is defined %}, "transition": {{ [5000, [0, (transition * 1000) | round(0) | int] | max] | min }}{% endif %}'
    light = {**common,"name":"Licht","unique_id":identifier+"_light_0","schema":"template",
             "command_topic":prefix+"/light/0/set","state_topic":prefix+"/light/0/status",
             "command_on_template":'{"turn":"on"{% if brightness is defined %},"brightness":{{ [100, [1, (brightness * 100 / 255) | round(0) | int] | max] | min }}{% endif %}'+transition+'}',
             "command_off_template":'{"turn":"off"'+transition+'}',
             "state_template":"{{ 'on' if value_json.ison else 'off' }}",
             "brightness_template":"{{ (value_json.brightness * 255 / 100) | round(0) | int }}",
             "retain":False,"optimistic":False}
    messages = [{"topic":f"homeassistant/light/{identifier}/light_0/config","payload":light}]
    for key,title,topic,dc,unit,sc,template in [
        ("power","Leistung","/light/0/power","power","W","measurement",None),
        ("energy","Energie","/light/0/energy","energy","kWh","total_increasing","{{ (value | float) / 60000 }}"),
        ("temperature","Gerätetemperatur","/temperature","temperature","°C","measurement",None)]:
        payload={**common,"name":title,"unique_id":identifier+"_"+key,"state_topic":prefix+topic,
                 "device_class":dc,"unit_of_measurement":unit,"state_class":sc}
        if key=="temperature":payload["entity_category"]="diagnostic"
        if template:payload["value_template"]=template
        messages.append({"topic":f"homeassistant/sensor/{identifier}/{key}/config","payload":payload})
    for index in (0,1):
        messages.append({"topic":f"homeassistant/binary_sensor/{identifier}/input_{index}/config",
                         "payload":{**common,"name":f"Eingang {index+1}","unique_id":f"{identifier}_input_{index}",
                                    "device_class":"power", "state_topic":f"{prefix}/input/{index}","payload_on":"1","payload_off":"0"}})
    # Diagnostics are sourced from Gen1 announce/info, not invented topics.
    for key, title, suffix, template, extra in [
        ("firmware", "Firmwareversion", "/announce", "{{ value_json.fw_ver }}", {}),
        ("ip", "IP-Adresse", "/announce", "{{ value_json.ip }}", {}),
        ("rssi", "WLAN-Signal", "/info", "{{ value_json.wifi_sta.rssi }}", {"device_class":"signal_strength", "unit_of_measurement":"dBm", "state_class":"measurement"}),
        ("ssid", "WLAN", "/info", "{{ value_json.wifi_sta.ssid }}", {}),
        ("uptime", "Betriebszeit", "/info", "{{ value_json.uptime }}", {"device_class":"duration", "unit_of_measurement":"s", "state_class":"measurement"}),
    ]:
        messages.append({"topic":f"homeassistant/sensor/{identifier}/{key}/config", "payload":{
            **common, "name":title, "unique_id":identifier+"_"+key,
            "entity_category":"diagnostic", "state_topic":prefix+suffix,
            "value_template":template, **extra}})
    for key, title, suffix, template in [
        ("firmware_available", "Firmwareupdate verfügbar", "/announce", "{{ 'ON' if value_json.new_fw else 'OFF' }}"),
        ("overtemperature", "Übertemperatur", "/info", "{{ 'ON' if value_json.overtemperature else 'OFF' }}"),
        ("overload", "Überlast", "/info", "{{ 'ON' if value_json.overload else 'OFF' }}"),
        ("loaderror", "Lastfehler", "/info", "{{ 'ON' if value_json.loaderror else 'OFF' }}"),
    ]:
        messages.append({"topic":f"homeassistant/binary_sensor/{identifier}/{key}/config", "payload":{
            **common, "name":title, "unique_id":identifier+"_"+key,
            "entity_category":"diagnostic", "device_class":"update" if key=="firmware_available" else "problem",
            "state_topic":prefix+suffix, "value_template":template,
            "payload_on":"ON", "payload_off":"OFF"}})
    messages.append({"topic":f"homeassistant/update/{identifier}/firmware_update/config", "payload":{
        **common, "name":"Firmware", "unique_id":identifier+"_firmware_update",
        "entity_category":"diagnostic", "device_class":"firmware", "state_topic":prefix+"/info",
        "value_template":"{{ value_json['update'].old_version }}",
        "latest_version_topic":prefix+"/info",
        "latest_version_template":"{{ value_json['update'].new_version or value_json['update'].old_version }}"}})
    messages.append({"topic":f"homeassistant/button/{identifier}/refresh/config", "payload":{
        **common, "name":"Diagnose aktualisieren", "unique_id":identifier+"_refresh",
        "entity_category":"diagnostic", "command_topic":prefix+"/command",
        "payload_press":"announce", "retain":False}})
    for message in messages:
        message["payload"]["enabled_by_default"] = True
    return messages
