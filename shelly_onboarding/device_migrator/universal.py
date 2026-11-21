"""Full, pinned bieniu model generators with isolated output and stable identities."""
from __future__ import annotations
import ast
from copy import deepcopy
from functools import lru_cache
import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import re
from .discovery import dimmer_discovery

_LOGGER = logging.getLogger(__name__)
VENDOR = Path(__file__).parent / 'vendor'


def valid_prefix(prefix):
    if not isinstance(prefix, str) or not prefix or len(prefix) > 200 or prefix.endswith('/') or any(c in prefix for c in '#+\x00\n\r ^'):
        raise ValueError('Vollständigen MQTT-Prefix ohne Wildcards, Leerzeichen oder abschließenden Slash angeben.')
    return prefix


def shelly_prefix(prefix):
    """Public discovery workflow follows the configured house namespace.

    Never rewrite a prefix silently: it determines existing device identities.
    The model generators and stored monitors can still read older namespaces.
    """
    valid_prefix(prefix)
    if not prefix.startswith('shellies/') or not prefix.removeprefix('shellies/'):
        raise ValueError('Im Tool den vollständigen MQTT-Prefix shellies/[Etage]/[Raum]/[Gerät] angeben. Im Gen1-Shelly nur [Etage]/[Raum]/[Gerät] eintragen; im Gen2/3/4-Shelly einschließlich shellies/.')
    if prefix.startswith('shellies/shellies/'):
        raise ValueError('shellies/ ist doppelt enthalten. Im Tool genau einmal shellies/ voranstellen; im Gen1-Shelly wird es automatisch ergänzt.')
    return prefix


@lru_cache(maxsize=4)
def generator_code(generation, definitions=False):
    if generation not in ('gen1', 'gen2'):
        raise ValueError('Generation muss gen1 oder gen2 (auch Gen3/4/BLU-Gateways) sein.')
    tree = ast.parse((VENDOR / (generation + '.py')).read_text())
    if generation == 'gen2' and not definitions:
        # Upstream appends each thermostat MAC to the previous sibling's ID.
        # Reset per thermostat so identities do not depend on discovery order.
        for node in tree.body:
            if isinstance(node, ast.If):
                for child in node.body:
                    if (isinstance(child, ast.For) and isinstance(child.iter, ast.Call)
                            and isinstance(child.iter.func, ast.Attribute)
                            and child.iter.func.attr == 'items'
                            and isinstance(child.iter.func.value, ast.Name)
                            and child.iter.func.value.id == 'blutrv_devices'):
                        child.body.insert(0, ast.parse('device_id = original_device_id').body[0])
    nodes = []
    for node in tree.body:
        if definitions:
            if generation == 'gen1' and isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'fw_ver' for t in node.targets):
                break
            if generation == 'gen2' and isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'device_id' for t in node.targets):
                break
        # Upstream MQTT/script side effects are replaced by capture functions.
        if isinstance(node, ast.FunctionDef) and node.name in ('mqtt_publish', 'current_script_installed', 'install_script', 'remove_old_script_versions'):
            continue
        if generation == 'gen1' and isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'default_topic' for t in node.targets):
            node.value = ast.parse("data['_topic_base']", mode='eval').body
        nodes.append(node)
    tree.body = nodes
    return compile(ast.fix_missing_locations(tree), str(VENDOR / (generation + '.py')), 'exec')


def run_generator(generation, data):
    messages = []
    def capture(topic, payload, retain=True, json=False):
        def convert(value):
            if isinstance(value, str):
                return value.replace('^', '"' if generation == 'gen2' or json else "'")
            if isinstance(value, list): return [convert(v) for v in value]
            if isinstance(value, dict): return {k:convert(v) for k,v in value.items()}
            return value
        if payload == '': return  # Never delete unrelated/pre-existing discovery.
        if not isinstance(payload, dict) or not topic.startswith('homeassistant/') or not topic.endswith('/config'):
            raise ValueError('Generator lieferte eine unerwartete Geräteaktion.')
        messages.append({'topic':topic, 'payload':convert(payload)})
    scope = {'data':deepcopy(data), 'logger':_LOGGER, 'mqtt_publish':capture,
             'current_script_installed':lambda:True,
             'install_script':lambda *args:None, 'remove_old_script_versions':lambda *args:None}
    exec(generator_code(generation), scope)
    return messages, scope


@lru_cache(maxsize=1)
def catalogue():
    result = []
    for gen in ('gen1','gen2'):
        scope={'logger':_LOGGER}
        exec(generator_code(gen, True), scope)
        if gen == 'gen1':
            for symbol,value in scope.items():
                if symbol.startswith('MODEL_') and symbol.endswith('_ID'):
                    name=scope.get(symbol[:-3])
                    if name:
                        result.append({'generation':1,'model':value,'name':name})
        else:
            for key,desc in scope['SUPPORTED_MODELS'].items():
                result.append({'generation':'BLU' if key.startswith('SB') else desc.get('gen',2),'model':key,'name':desc.get('name',key)})
    return sorted(result,key=lambda x:(str(x['generation']),x['name']))


def full_topic(value, base):
    if isinstance(value,str):
        if value.startswith('~'): return base+value[1:]
        if value.endswith('~'): return value[:-1]+base
    return value


def namespace_messages(messages, prefix, generation, ip=None, name=None):
    """Separate MQTT devices from native integration and other discovery scripts."""
    root_id='dms_'+hashlib.sha256(prefix.encode()).hexdigest()[:20]
    id_map={}
    for msg in messages:
        dev=msg['payload'].get('dev',msg['payload'].get('device',{}))
        ids=dev.get('ids',dev.get('identifiers',[])) or [c[1] for c in dev.get('cns',dev.get('connections',[])) if c[0]=='mac']; ids=[ids] if isinstance(ids,str) else ids
        for old in ids:
            id_map[old] = root_id if not dev.get('via_device') else 'dms_'+hashlib.sha256(str(old).encode()).hexdigest()[:20]
    # Gateway child identities may use via_dev abbreviation.
    for msg in messages:
        dev=msg['payload'].get('dev',msg['payload'].get('device',{}))
        if dev.get('via_dev') or dev.get('via_device'):
            ids=dev.get('ids',dev.get('identifiers',[])) or [c[1] for c in dev.get('cns',dev.get('connections',[])) if c[0]=='mac'];ids=[ids] if isinstance(ids,str) else ids
            for old in ids:id_map[old]='dms_'+hashlib.sha256(str(old).encode()).hexdigest()[:20]
    out=[]
    for msg in messages:
        p=deepcopy(msg['payload']); dev=p.get('dev',p.get('device',{}))
        ids=dev.get('ids',dev.get('identifiers',[])) or [c[1] for c in dev.get('cns',dev.get('connections',[])) if c[0]=='mac'];ids=[ids] if isinstance(ids,str) else ids
        dev.pop('connections',None);dev.pop('cns',None)
        dev.pop('ids',None);dev['identifiers']=[id_map[x] for x in ids]
        via=dev.pop('via_dev',dev.pop('via_device',None))
        if via:dev['via_device']=id_map.get(via,root_id)
        if ip and not via: dev['configuration_url']=f'http://[{ip}]/' if ':' in ip else f'http://{ip}/';dev.pop('cu',None)
        if name and not via: dev['name']=name;dev.pop('name_by_user',None)
        p.pop('dev',None);p['device']=dev
        unique=p.pop('uniq_id',p.pop('unique_id',None))
        if unique:p['unique_id']='dms_'+str(unique)
        component=msg['topic'].split('/')[1]
        oid='dms_'+hashlib.sha256(msg['topic'].encode()).hexdigest()[:24]
        out.append({'topic':f'homeassistant/{component}/{oid}/config','payload':p})
    return out, root_id


def build_discovery(generation, prefix, data, ip=None, name=None, options=None):
    valid_prefix(prefix)
    if ip:ipaddress.ip_address(ip)
    if not isinstance(data,dict):raise ValueError('Gerätedaten müssen ein JSON-Objekt sein.')
    data=deepcopy(data)
    if generation=='gen1':
        # Use a logical ID derived from MAC: upstream's 32-char limit need not
        # restrict custom MQTT topic paths. The actual topic base is kept intact.
        model=data.get('model')
        if not model:raise ValueError('Gen1-Announce muss das Modell enthalten.')
        mac=re.sub('[^0-9a-fA-F]','',str(data.get('mac','')))
        if len(mac)!=12:raise ValueError('Gen1-Announce enthält keine gültige MAC-Adresse.')
        if not re.match(r'^\d{8}-',str(data.get('fw_ver',''))):raise ValueError('Gen1-Firmwarekennung muss aus der Announce-Antwort stammen (YYYYMMDD-…).')
        data['id']='migrator-'+mac.lower()
        data['host']=ip or data.get('ip')
        data['_topic_base']=prefix+'/'
        if options:
            if not isinstance(options,dict):raise ValueError('Optionen müssen ein JSON-Objekt sein.')
            data[data['id']]=deepcopy(options)
        data['discovery_prefix']='homeassistant'
    elif generation=='gen2':
        if options:raise ValueError('Gen2/3/4 lesen Optionen direkt aus der Gerätekonfiguration.')
        config=data.get('device_config',{})
        if config.get('mqtt',{}).get('topic_prefix') != prefix:
            # Component-only gateway configurations carry MQTT in components.
            def find_mqtt(obj):
                if isinstance(obj,dict):
                    if obj.get('key')=='mqtt':return obj.get('config',{}).get('topic_prefix')
                    for v in obj.values():
                        found=find_mqtt(v)
                        if found:return found
                if isinstance(obj,list):
                    for v in obj:
                        found=find_mqtt(v)
                        if found:return found
                return None
            if find_mqtt(config.get('components'))!=prefix:
                raise ValueError('MQTT-Prefix stimmt nicht mit der gelesenen Gerätekonfiguration überein.')
        data['script_prefix']='device_migrator'
        data['discovery_prefix']='homeassistant'
    else:raise ValueError('Unbekannte Generation.')
    raw,scope=run_generator(generation,data)
    if generation == 'gen2':
        # Vendor channel subdevices use parent-MAC-N; these are one physical unit.
        # BLE/gateway children have independent hardware IDs and stay separate.
        roots = {}
        for message in raw:
            device = message['payload'].get('dev', message['payload'].get('device', {}))
            if device.get('via_dev') or device.get('via_device'):
                continue
            ids = device.get('ids', device.get('identifiers', []))
            ids = [ids] if isinstance(ids, str) else ids
            for identifier in ids:
                roots[str(identifier).lower()] = device
        for message in raw:
            payload = message['payload']
            device = payload.get('dev', payload.get('device', {}))
            via = str(device.get('via_dev', device.get('via_device', ''))).lower()
            ids = device.get('ids', device.get('identifiers', []))
            ids = [ids] if isinstance(ids, str) else ids
            if via in roots and ids and all(re.fullmatch(re.escape(via) + r'-\d+', str(identifier).lower()) for identifier in ids):
                payload.pop('dev', None)
                payload['device'] = deepcopy(roots[via])
    if not raw:raise ValueError('Für diese Konfiguration wurden keine Entitäten erzeugt.')
    messages,root_id=namespace_messages(raw,prefix,generation,ip,name)
    battery=bool(scope.get('battery_powered')) if generation=='gen1' else scope.get('wakeup_period',0)>0
    # Preserve all existing Dimmer 1/2 MQTT IDs and command templates.
    if generation=='gen1' and model in ('SHDM-1','SHDM-2'):
        messages=merge_legacy_dimmer(messages,prefix,ip or data['host'],name or 'Shelly MQTT Dimmer')
        root_id=messages[0]['payload']['device']['identifiers'][0]
    # Native Shelly inputs use binary_sensor power (boolean presence), not the
    # numeric sensor power class. Keep IDs/topics and the vendor source intact.
    for message in messages:
        payload=message['payload']
        # Shelly's native roller/cover entities are shutters. The upstream
        # discovery omits this class; keep its commands and identity intact.
        if (message['topic'].split('/')[1]=='cover'
                and (generation=='gen1' or payload.get('unique_id','').startswith('dms_shelly'))
                and payload.get('device_class',payload.get('dev_cla')) is None):
            payload['device_class']='shutter'
        if (message['topic'].split('/')[1]=='binary_sensor'
                and re.search(r'(?:^|[-_])(?:input[-_:]\d+|\d+[-_]input)$',payload.get('unique_id',''))
                and payload.get('device_class',payload.get('dev_cla')) is None):
            payload['device_class']='power'
    if generation == 'gen2':
        config = data.get('device_config', {})
        components = config.get('components', [])
        has_sys = isinstance(config.get('sys'), dict) or any(
            isinstance(c, dict) and c.get('key') == 'sys' for c in components)
        root = next((m['payload'] for m in messages
                     if m['payload']['device']['identifiers'] == [root_id]
                     and not m['payload']['device'].get('via_device')), None)
        if has_sys and root:
            payload = {
                'name': 'Restart required', 'unique_id': root_id + '_restart_required',
                'device_class': 'problem', 'entity_category': 'diagnostic',
                'state_topic': prefix + '/status/sys',
                'value_template': "{{ 'ON' if value_json.restart_required is sameas true else 'OFF' if value_json.restart_required is sameas false else 'unknown' }}",
                'payload_on': 'ON', 'payload_off': 'OFF',
                'device': deepcopy(root['device']),
            }
            for key in ('~', 'availability', 'avty', 'availability_mode', 'avty_mode'):
                if key in root:
                    payload[key] = deepcopy(root[key])
            messages.append({'topic': 'homeassistant/binary_sensor/' + root_id + '/restart_required/config',
                             'payload': payload})
    if generation == 'gen2':
        # Separate numeric brightness control, like the existing Gen1 discovery.
        # Use only actual Light components; color components have other RPCs.
        for light in list(messages):
            source = light['payload']
            state_topic = source.get('state_topic', source.get('stat_t', ''))
            component = re.search(r'/status/light:(\d+)$', state_topic.replace('~', prefix + '/'))
            if light['topic'].split('/')[1] != 'light' or not component:
                continue
            channel = int(component[1])
            unique = source['unique_id'] + '_brightness'
            payload = {
                'name': f'Brightness {channel}', 'unique_id': unique,
                'device': deepcopy(source['device']),
                'state_topic': prefix + f'/status/light:{channel}',
                'value_template': '{{ value_json.brightness }}',
                'command_topic': prefix + '/rpc',
                # Match the proven light command's reply route and integer scale.
                'command_template': '{"id":1,"src":' + json.dumps(scope['source_topic']) + ',"method":"Light.Set","params":{"id":' + str(channel) + ',"on":{{ "true" if value | int > 0 else "false" }},"brightness":{{ value | int }}}}',
                'min': 0, 'max': 100, 'step': 1, 'mode': 'slider',
                'unit_of_measurement': '%', 'icon': 'mdi:brightness-percent',
                'enabled_by_default': True, 'retain': False,
            }
            for key in ('~', 'availability', 'avty', 'availability_mode', 'avty_mode'):
                if key in source:
                    payload[key] = deepcopy(source[key])
            messages.append({'topic': 'homeassistant/number/' + root_id + f'/brightness_{channel}/config', 'payload': payload})
    # Child IDs are present on the climate entity, not on every child function.
    # Resolve by device identity so every function checks the same TRV's link.
    trv_ids = {}
    for message in messages:
        p = message['payload']
        if message['topic'].split('/')[1] == 'climate' and p['device'].get('model', p['device'].get('mdl')) == 'Shelly BLU TRV':
            match = re.search(r'-(2\d\d)$', p.get('unique_id', ''))
            if match:
                trv_ids[tuple(p['device']['identifiers'])] = match[1]
    # All generated entities are usable at first discovery, across generations.
    # Existing registry choices remain HA-owned.
    for message in messages:
        payload = message['payload']
        payload.pop('en', None)
        payload['enabled_by_default'] = True
        if generation == 'gen2' and payload['device'].get('model',payload['device'].get('mdl')) == 'Shelly BLU TRV':
            platform = message['topic'].split('/')[1]
            unique = payload.get('unique_id', '')
            if platform == 'sensor' and unique.endswith(('-battery', '-valve_position')):
                payload.pop('stat_cla', None)
                payload['state_class'] = 'measurement'
            if platform == 'number' and unique.endswith('-external_temperature'):
                payload.pop('dev_cla', None)
                payload['device_class'] = 'temperature'
                # This is a write-only input, not the measured room temperature.
                payload['optimistic'] = True
                payload['retain'] = False
            tid = trv_ids.get(tuple(payload['device']['identifiers']))
            if tid:
                availability = payload.pop('avty',payload.pop('availability', []))
                if isinstance(availability,dict):availability=[availability]
                availability.append({'topic':prefix + '/status/blutrv:' + tid,
                    'value_template':"{{ 'online' if value_json.connected is sameas true else 'offline' }}",
                    'payload_available':'online','payload_not_available':'offline'})
                payload['availability']=availability
                payload.pop('avty_mode', None)
                payload['availability_mode']='all'
    counts={}
    for m in messages:
        platform=m['topic'].split('/')[1];counts[platform]=counts.get(platform,0)+1
    return {'messages':messages, 'counts':counts, 'device_count':len({tuple(m['payload']['device']['identifiers']) for m in messages}),
            'monitor':{'generation':generation,'prefix':prefix,'id':data['id'],
                       'battery':battery, 'dynamic': any(c.get('key','').startswith(('blutrv:', 'bthomedevice:', 'bthomesensor:')) for c in data.get('device_config',{}).get('components',[])),
                       'version':data.get('fw_ver') or data.get('device_config',{}).get('sys',{}).get('device',{}).get('fw_id','').split('/')[ -1].split('-')[0]},
            'root_id':root_id}


def merge_legacy_dimmer(messages,prefix,ip,name):
    legacy=dimmer_discovery(prefix,ip,name)
    dev=legacy[0]['payload']['device']
    if messages:
        source_dev=messages[0]['payload']['device']
        if source_dev.get('sw'):dev['sw_version']=source_dev['sw']
        elif source_dev.get('sw_version'):dev['sw_version']=source_dev['sw_version']
    for existing in legacy:
        if '/update/' in existing['topic']:
            existing['payload'].update({'command_topic':prefix+'/command','payload_install':'update_fw','retain':False})
    # Skip semantically identical upstream entities; retain all other functions.
    legacy_keys={'light','power','energy','temperature','rssi','ssid','ip','overtemperature','firmware'}
    extra=[]
    for m in messages:
        p=m['payload'];u=p.get('unique_id','').lower();platform=m['topic'].split('/')[1]
        base=p.get('~','');state=full_topic(p.get('stat_t',p.get('state_topic')),base)
        if platform=='light':continue
        if platform=='update':continue
        if platform=='sensor' and (any(u.endswith('-'+k) or u.endswith('-'+k+'-0') for k in legacy_keys) or state in (prefix+'/light/0/power',prefix+'/light/0/energy',prefix+'/temperature')):continue
        if platform=='binary_sensor' and (any(u.endswith('-'+key) for key in ('overtemperature','overload','loaderror','input-0','input-1'))):continue
        p['device']=deepcopy(dev)
        extra.append(m)
    return legacy+extra
