import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from urllib.parse import quote, urlsplit

import aiohttp
from aiohttp import web
from logic import discovery, extend, local_ip, plan_fields, plug, radio
from logic import PLUG_UI, SWITCH_PROTECTION, compatible_settings, setting_values, template_settings

ROOT = Path("/data")
AP = "192.168.33.1"
FACTORY = re.compile(r"shelly[\w-]*-([a-f0-9]{12})", re.I)


class Assistant:
    def __init__(self, directory=ROOT):
        self.directory = directory
        self.options = json.loads((directory / "options.json").read_text())
        self.path = directory / "onboarding.json"
        self.db = json.loads(self.path.read_text()) if self.path.exists() else {}
        for key in ("jobs", "seen", "ignored", "backups"):
            self.db.setdefault(key, {})
        self.aps = []
        self.notice = ""
        self.task = None
        self.lock = asyncio.Lock()
        self.headers = {"Authorization": "Bearer " + os.environ["SUPERVISOR_TOKEN"]}

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.db, ensure_ascii=False))
        tmp.replace(self.path)

    async def call(self, path, body=None):
        async with self.http.request("GET" if body is None else "POST", "http://supervisor/" + path,
                                     headers=self.headers, json=body, allow_redirects=False) as r:
            if r.status >= 300:
                raise ValueError(f"HA {path.split('?')[0]} meldet HTTP {r.status}.")
            data = await r.json(content_type=None)
            if not path.startswith("core/api/"):
                if data.get("result") != "ok":
                    raise ValueError("Supervisor hat die Anfrage abgelehnt.")
                return data["data"]
            return data

    async def ws(self, kind, **kw):
        async with self.http.ws_connect("ws://supervisor/core/websocket", headers=self.headers, timeout=10) as sock:
            await sock.receive_json(timeout=12)
            await sock.send_json({"type":"auth", "access_token":os.environ["SUPERVISOR_TOKEN"]})
            if (await sock.receive_json(timeout=12))["type"] != "auth_ok":
                raise ValueError("HA-WebSocket-Anmeldung fehlgeschlagen.")
            await sock.send_json(dict(type=kind, id=1, **kw))
            res = await sock.receive_json(timeout=15)
            if not res.get("success"):
                raise ValueError("HA lehnt " + kind + " ab.")
            return res["result"]

    async def rpc(self, ip, method, params=None, auth=False):
        ip = local_ip(ip)
        payload = {"id":1, "method":method, "params":params or {}}
        middlewares = ()
        if auth and self.options["shelly_admin_password"]:
            middlewares = (aiohttp.DigestAuthMiddleware("admin", self.options["shelly_admin_password"]),)
        async with self.http.post(f"http://{ip}/rpc", json=payload, middlewares=middlewares,
                                  allow_redirects=False, timeout=aiohttp.ClientTimeout(total=7)) as r:
            if r.status != 200:
                raise ValueError(f"{method}: HTTP {r.status}")
            data = await r.json(content_type=None)
            if "result" not in data:
                raise ValueError(f"{method}: Gerät meldet Fehler {data.get('error', {}).get('code')}")
            return data["result"]

    async def service(self, domain, service, body):
        return await self.call(f"core/api/services/{domain}/{service}", body)

    @property
    def iface(self):
        return quote(self.options["wifi_interface"], safe="")

    async def scan(self):
        if self.db.get("lease"):
            return
        result = await self.call(f"network/interface/{self.iface}/accesspoints")
        aps = result["accesspoints"] if isinstance(result, dict) else result
        self.aps = sorted({a["ssid"] for a in aps if FACTORY.fullmatch(a.get("ssid") or "")})
        for ap in self.aps:
            if ap in self.db["seen"] or ap in self.db["ignored"]:
                continue
            await self.service("persistent_notification", "create", {
                "title":"Neuen Shelly gefunden", "message":f"{ap} ist in Funkreichweite. Öffne Shelly Onboarding für die Einrichtung.",
                "notification_id":"onboarding_" + ap.lower()})
            self.db["seen"][ap] = True
            self.save()
        self.notice = ""

    async def watch(self):
        while True:
            try:
                if not self.lock.locked() and not (self.task and not self.task.done()):
                    await self.scan()
            except Exception as e:
                self.notice = f"WLAN-Scan: {str(e) or type(e).__name__}"
            await asyncio.sleep(self.options["scan_interval"])

    async def release_radio(self):
        lease = self.db.get("lease")
        if lease:
            net = await self.call("network/info")
            wlan = next(d for d in net["interfaces"] if d["interface"] == lease["interface"])
            ssid = (wlan.get("wifi") or {}).get("ssid")
            if wlan.get("primary") or ssid and ssid != lease["ssid"]:
                raise ValueError("WLAN wurde extern geändert. Adapter in HA prüfen.")
            # Disabling the dedicated adapter also disconnects a factory AP.
            await self.call("network/interface/" + quote(lease["interface"], safe="") + "/update", {"enabled":False})
            del self.db["lease"]
            self.save()

    async def inventory(self):
        devices, entities, areas, labels = await asyncio.gather(*(
            self.ws("config/" + k + "_registry/list") for k in ("device","entity","area","label")))
        sources = []
        for d in devices:
            if "shelly" not in json.dumps([d.get("manufacturer"),d.get("identifiers")]).lower():
                continue
            host = urlsplit(d.get("configuration_url") or "").hostname or ""
            installed = next((j for j in self.db["jobs"].values() if j.get("entity") and any(
                e["entity_id"]==j["entity"] and e.get("device_id")==d["id"] for e in entities)),None)
            if installed:
                host = installed["ip"]
            try:
                host = local_ip(host)
            except ValueError:
                host = ""
            switches = [e["entity_id"] for e in entities if e.get("device_id") == d["id"] and e["entity_id"].startswith("switch.") and not e.get("disabled_by")]
            macs = [v.replace(":","").lower() for k,v in d.get("connections",[]) if k=="mac"]
            for _, value in d.get("identifiers", []):
                match = re.search(r"([a-f\d]{12})$",value,re.I)
                if match:
                    macs.append(match[1].lower())
            identifiers = [v for _,v in d.get("identifiers",[])]
            if installed:
                macs.append(installed["mac"])
            for ent in entities:
                if ent.get("device_id")==d["id"]:
                    match = re.search(r"shelly[a-z0-9]+-([a-f0-9]{12})(?:-|_|$)",str(ent.get("unique_id","")),re.I)
                    if match:
                        macs.append(match[1].lower())
                        break
            sources.append(dict(identifiers=identifiers,id=d["id"], name=d.get("name_by_user") or d.get("name"), model=d.get("model"),
                                ip=host, switches=switches, macs=macs, area=d.get("area_id")))
        return dict(sources=sources,areas=areas,labels=labels)

    async def template(self, data):
        src = next((s for s in (await self.inventory())["sources"] if s["id"] == data["source"]),None)
        if not src:
            raise ValueError("Vorlage ist nicht mehr registriert.")
        ip = local_ip(data["ip"] or src["ip"])
        info = await self.rpc(ip,"Shelly.GetDeviceInfo")
        mac = plug(info)
        if mac not in src["macs"]:
            raise ValueError("Die Geräteidentität passt nicht zur gewählten HA-Vorlage.")
        config = await self.rpc(ip,"Shelly.GetConfig",auth=True)
        if not any(PLUG_UI.fullmatch(key) for key in config):
            # Some firmware versions expose the LED component via its own getter.
            for method in (await self.rpc(ip, "Shelly.ListMethods", auth=True)).get("methods", []):
                namespace, _, action = method.partition(".")
                if action == "GetConfig" and PLUG_UI.fullmatch(namespace):
                    config[namespace.lower()] = await self.rpc(ip, method, auth=True)
        settings, skipped = template_settings(config)
        mqtt = config["mqtt"]
        return dict(ssid=config["wifi"]["sta"]["ssid"],broker=mqtt.get("server"),user=mqtt.get("user"),
                    tls=mqtt.get("ssl_ca") or "off", initial_state=config["switch:0"]["initial_state"],
                    area=src["area"], source_topic=mqtt.get("topic_prefix") or info["id"],
                    settings=settings, skipped=skipped, model=info.get("model"))

    async def apply_template_settings(self, job, info):
        template = job["template"]
        ip = job["ip"]
        expected, warnings = [], []
        restart = False
        for key, entry in template["settings"].items():
            namespace = entry["method"]
            params = {"id": 0} if key == "switch:0" else {}
            source = entry["config"]
            try:
                current = await self.rpc(ip, namespace + ".GetConfig", params)
                selected = compatible_settings(source, current)
                if key == "switch:0" and (not template["model"] or template["model"] != info.get("model")):
                    selected = {field: value for field, value in selected.items() if field not in SWITCH_PROTECTION}
                unavailable = sorted(setting_values(source, key).keys() - setting_values(selected, key).keys())
                warnings.extend(f"{path}: vom Zielgerät nicht übernommen." for path in unavailable)
                if selected and compatible_settings(current, selected) != selected:
                    response = await self.rpc(ip, namespace + ".SetConfig", {**params, "config": selected})
                    restart |= bool(response.get("restart_required"))
                if selected:
                    expected.append((key, namespace, params, selected))
            except (ValueError, TimeoutError, aiohttp.ClientError) as error:
                warnings.append(f"{key}: {error or type(error).__name__}")
        return restart, expected, warnings

    async def verify_template_settings(self, ip, expected, warnings):
        confirmed = []
        for key, namespace, params, settings in expected:
            try:
                actual = await self.rpc(ip, namespace + ".GetConfig", params)
                readback = setting_values(actual, key)
                for path, value in setting_values(settings, key).items():
                    if path in readback and value == readback[path]:
                        confirmed.append(path)
                    else:
                        warnings.append(f"{path}: Zielwert konnte nicht bestätigt werden.")
            except (ValueError, TimeoutError, aiohttp.ClientError) as error:
                warnings.append(f"{key}: Kontrolle fehlgeschlagen ({error or type(error).__name__}).")
        return sorted(confirmed)

    async def identify(self, ip, expected):
        info = await self.rpc(ip, "Shelly.GetDeviceInfo")
        if plug(info) != expected:
            raise ValueError("MAC stimmt nicht mit dem ausgewählten Plug überein.")
        return info

    async def wait_ip(self, job, attempts=45):
        for _ in range(attempts):
            if job.get("ip"):
                try:
                    return await self.identify(job["ip"],job["mac"])
                except (aiohttp.ClientError,ValueError,TimeoutError):
                    pass
            await asyncio.sleep(2)
        raise ValueError("Plug nicht erreichbar. DHCP-Adresse prüfen und mit Ziel-IP fortsetzen.")

    def phase(self, job, step):
        job.update(step=step,error="")
        self.save()

    async def run(self, job):
        p = job["plan"]
        opt = self.options
        try:
            if job["step"] == "WLAN":
                await self.release_radio()
                radio(await self.call("network/info"), opt["wifi_interface"])
                self.db["lease"] = {"interface":opt["wifi_interface"],"ssid":job["ap"]}
                self.save()
                try:
                    await self.call(f"network/interface/{self.iface}/update", {
                        "enabled":True,"wifi":{"ssid":job["ap"],"auth":"open","mode":"infrastructure"},
                        "ipv4":{"method":"static","address":["192.168.33.2/24"]},"ipv6":{"method":"disabled"}})
                    info = await self.wait_ip(dict(ip=AP,mac=job["mac"]), 8)
                    if "switch:0" not in await self.rpc(AP,"Shelly.GetConfig"):
                        raise ValueError("Dieser Plug besitzt keinen schaltbaren Ausgang.")
                    await self.rpc(AP,"WiFi.SetConfig",{"config":{"sta":{"enable":True,"ssid":p["ssid"],
                                   "pass":opt["wifi_password"],"ipv4mode":"dhcp"}}})
                    for _ in range(30):
                        await asyncio.sleep(2)
                        try:
                            await self.identify(AP,job["mac"])
                            status = await self.rpc(AP,"WiFi.GetStatus")
                        except (aiohttp.ClientError, TimeoutError):
                            continue
                        if status.get("sta_ip") and status.get("ssid") == p["ssid"]:
                            job["ip"] = local_ip(status["sta_ip"])
                            self.phase(job,"Firmware")
                            break
                    else:
                        raise ValueError("Keine DHCP-Adresse erhalten. WLAN-Profil prüfen oder mit Ziel-IP fortsetzen.")
                finally:
                    await self.release_radio()
            info = await self.wait_ip(job)
            ip = job["ip"]
            if job["step"] == "Firmware":
                if "switch:0" not in await self.rpc(ip,"Shelly.GetConfig"):
                    raise ValueError("Dieser Plug besitzt keinen schaltbaren Ausgang.")
                attempted_versions = set()
                while update := (await self.rpc(ip,"Shelly.CheckForUpdate")).get("stable"):
                    version = update.get("version")
                    if not version:
                        raise ValueError("Shelly meldet ein Firmwareupdate ohne Versionsnummer.")
                    if version == info.get("ver") or version in attempted_versions:
                        raise ValueError(f"Shelly meldet Firmware {version} erneut. Bitte später fortsetzen.")
                    attempted_versions.add(version)
                    await self.rpc(ip,"Shelly.Update",{"stage":"stable"})
                    await asyncio.sleep(30)
                    for attempt in range(55):
                        if attempt:
                            await asyncio.sleep(3)
                        try:
                            info = await self.identify(ip,job["mac"])
                        except (ValueError,TimeoutError,aiohttp.ClientError):
                            continue
                        if info.get("ver") == version:
                            break
                    else:
                        raise ValueError("Firmwareversion noch nicht bestätigt.")
                self.phase(job,"MQTT")
            if job["step"] == "MQTT":
                restart, expected, warnings = False, [], []
                if "template" in job:
                    restart, expected, warnings = await self.apply_template_settings(job, info)
                if p["tls"]=="user_ca.pem":
                    cert = opt["ca_pem"].strip()+"\n"
                    for offset in range(0,len(cert),1000):
                        await self.rpc(ip,"Shelly.PutUserCA",{"data":cert[offset:offset+1000],"append":bool(offset)})
                await self.rpc(ip,"Sys.SetConfig",{"config":{"device":{"name":p["name"]}}})
                await self.rpc(ip,"Switch.SetConfig",{"id":0,"config":{"initial_state":p["initial_state"]}})
                res = await self.rpc(ip,"MQTT.SetConfig",{"config":{"enable":True,"server":p["broker"],
                    "user":p["user"] or None,"pass":opt["mqtt_password"],"ssl_ca":None if p["tls"]=="off" else p["tls"],
                    "topic_prefix":p["topic"],"client_id":info["id"],"enable_control":True,"enable_rpc":True,"rpc_ntf":True,"status_ntf":True}})
                if restart or res.get("restart_required"):
                    await self.rpc(ip,"Shelly.Reboot")
                    await asyncio.sleep(7)
                for _ in range(25):
                    try:
                        await self.identify(ip,job["mac"])
                        if (await self.rpc(ip,"MQTT.GetStatus")).get("connected"):
                            break
                    except (aiohttp.ClientError,ValueError,TimeoutError):
                        pass
                    await asyncio.sleep(2)
                else:
                    raise ValueError("Keine Brokerverbindung. DNS, TLS, Zugang und ACL prüfen.")
                if "template" in job:
                    job["template_confirmed"] = await self.verify_template_settings(ip, expected, warnings)
                    job["template_warnings"] = warnings
                self.phase(job,"Discovery")
            if job["step"]=="Discovery":
                config = await self.rpc(ip,"Shelly.GetConfig")
                messages, unique = discovery(info,p,opt["discovery_prefix"],config,ip)
                async def publish(topic, payload, retain=False):
                    await self.service("mqtt","publish",dict(topic=topic,payload=payload,retain=retain,qos=1))
                for message in messages:
                    await publish(message["topic"],json.dumps(message["payload"]),True)
                job["entities_published"] = len(messages)
                for _ in range(20):
                    await asyncio.sleep(2)
                    await self.refresh_status(job)
                    entities = await self.ws("config/entity_registry/list")
                    entity = next((e for e in entities if e["platform"]=="mqtt" and e.get("unique_id")==unique),None)
                    if entity:
                        state = await self.call("core/api/states/"+entity["entity_id"])
                        if state.get("state") in ("on","off"):
                            if p["area"]:
                                await self.ws("config/device_registry/update",device_id=entity["device_id"],area_id=p["area"])
                            if job.get("ap"):
                                await self.identify(ip,job["mac"])
                                await self.rpc(ip,"WiFi.SetConfig",{"config":{"ap":{"enable":False}}})
                            job["entity"] = entity["entity_id"]
                            self.phase(job,"Fertig")
                            break
                else:
                    raise ValueError("MQTT-Schalter in HA noch nicht verfügbar. Discovery-Präfix und ACL prüfen.")
        except Exception as e:
            job["error"] = str(e) or type(e).__name__
            self.save()

    async def refresh_status(self,job):
        info = await self.identify(job["ip"],job["mac"])
        status = await self.rpc(job["ip"],"Shelly.GetStatus")
        status.setdefault("sys",{})["installed_version"] = info.get("ver","")
        topic = job["plan"]["topic"]
        updates = [("/status/rpc",json.dumps(status)),("/command/switch:0","status_update")]
        if (status.get("mqtt") or {}).get("connected"):
            updates.append(("/online","true"))
        updates.append(("/status/sys",json.dumps(status["sys"])))
        for suffix,payload in updates:
            await self.service("mqtt","publish",dict(topic=topic+suffix,payload=payload,retain=False,qos=1))

    async def monitor(self):
        while True:
            for job in list(self.db["jobs"].values()):
                if job["step"]=="Fertig":
                    try:
                        await self.refresh_status(job)
                    except (ValueError,TimeoutError,aiohttp.ClientError):
                        continue
            await asyncio.sleep(120)

    async def effects(self, data, job):
        old = data["old"]
        inventory = await self.inventory()
        source = next((s for s in inventory["sources"] if old in s["switches"]),None)
        if not source or old == job["entity"]:
            raise ValueError("Anderen Referenzschalter auswählen.")
        requested = data.get("apply_all")
        if requested is None:
            requested = {data["apply"]: data.get("digest")} if data.get("apply") else {}
        if not isinstance(requested, dict):
            raise ValueError("Ungültige Auswahl zur Übernahme.")
        refs, skipped = [], []
        pending = {}
        for state in await self.call("core/api/states"):
            domain, key = state["entity_id"].split(".",1)
            if domain not in ("automation","script"):
                continue
            if domain == "automation":
                key = state["attributes"].get("id")
            path = f"core/api/config/{domain}/config/{quote(str(key),safe='')}"
            try:
                if not key:
                    raise ValueError()
                cfg = await self.call(path)
                if not isinstance(cfg,dict):
                    raise ValueError()
            except ValueError:
                skipped.append(state["entity_id"])
                continue
            raw = json.dumps(cfg)
            if old not in raw and source["id"] not in raw:
                continue
            updated, changes = extend(cfg, old, job["entity"])
            digest = hashlib.sha256(raw.encode()).hexdigest()
            refs.append(dict(path=path,name=state["entity_id"],changes=changes,digest=digest))
            if path in requested:
                if requested[path] != digest or not changes:
                    raise ValueError("Vorschau veraltet. Bitte erneut prüfen.")
                pending[path] = (state["entity_id"], cfg, updated)
        if not requested:
            return dict(refs=refs,skipped=skipped)
        if pending.keys() != requested.keys():
            raise ValueError("Eine Änderung ist nicht mehr verfügbar. Bitte erneut prüfen.")

        saved, failed = [], []
        for path, (entity, before, after) in pending.items():
            try:
                if await self.call(path) != before:
                    raise ValueError("Konfiguration wurde seit der Vorschau geändert.")
                backup_id = job["mac"] + ":" + entity
                self.db["backups"][backup_id] = {"path": path, "before": before, "after": after}
                self.save()
                await self.call(path, after)
            except (ValueError, TimeoutError, aiohttp.ClientError) as error:
                failed.append({"name": entity, "error": str(error) or type(error).__name__})
            else:
                saved.append(entity)
        return dict(saved=saved, failed=failed)

    async def action(self, action, d):
        jobs = self.db["jobs"]
        busy = self.task and not self.task.done()
        if action=="state":
            return dict(aps=[a for a in self.aps if a not in self.db["ignored"] and FACTORY.fullmatch(a)[1].lower() not in jobs],
                        ignored=list(self.db["ignored"]),notice=self.notice,
                        jobs={mac: {key: value for key, value in job.items() if key != "template"} for mac, job in jobs.items()},
                        busy=bool(busy),
                        backups=list(self.db["backups"]),profile={k:self.options[k] for k in ("ssid","broker","tls","mqtt_user")})
        if action=="inventory":
            return await self.inventory()
        if action=="template":
            template = await self.template(d)
            settings = template.pop("settings")
            template["field_paths"] = sorted(path for key, entry in settings.items() for path in setting_values(entry["config"], key))
            return template
        if busy:
            raise ValueError("Eine Einrichtung läuft bereits.")
        if action=="discard":
            job = jobs[d["mac"]]
            if job["step"]=="Fertig":
                raise ValueError("Abgeschlossene Einrichtung bleibt registriert.")
            await self.release_radio()
            del jobs[d["mac"]]
            self.save()
        elif action=="scan":
            await self.scan()
        elif action=="ignore":
            if d["ap"] in self.db["ignored"]:
                self.db["ignored"].pop(d["ap"])
            elif d["ap"] in self.aps:
                self.db["ignored"][d["ap"]] = True
            self.save()
        elif action=="start":
            p = plan_fields(d)
            ap = d.get("ap")
            if ap:
                if self.options["wifi_password"] == "":
                    raise ValueError("WLAN-Passwort im lokalen Profil ergänzen.")
                if ap not in self.aps or not FACTORY.fullmatch(ap):
                    raise ValueError("Werks-WLAN erneut suchen.")
                mac = FACTORY.fullmatch(ap)[1].lower()
                step, ip = "WLAN", None
            else:
                ip = local_ip(d["ip"])
                info = await self.rpc(ip,"Shelly.GetDeviceInfo")
                mac, step = plug(info),"Firmware"
                if d.get("expected","").lower()!=mac:
                    raise ValueError("MAC für die manuelle Inbetriebnahme stimmt nicht überein.")
            if mac in jobs:
                raise ValueError("Vorgang existiert bereits. Bitte fortsetzen.")
            if p["broker"] != self.options["broker"] or p["ssid"] != self.options["ssid"] or p["user"] != self.options["mqtt_user"]:
                raise ValueError("Zugangsdaten gehören zum lokalen Profil. SSID, Broker und Benutzer zuerst in der App-Konfiguration anpassen.")
            if p["tls"] != self.options["tls"]:
                raise ValueError("TLS-Modus muss zum lokalen Profil passen.")
            if p["tls"]=="user_ca.pem":
                try:
                    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=self.options["ca_pem"])
                except (ssl.SSLError, ValueError) as e:
                    raise ValueError("Gültiges PEM-CA-Zertifikat im lokalen Profil hinterlegen.") from e
            template = None
            if d.get("source"):
                template = await self.template({"source":d["source"],"ip":d.get("source_ip","")})
                if template["source_topic"]==p["topic"]:
                    raise ValueError("Das Topic der Vorlage ist bereits belegt.")
            if any(j["plan"]["topic"]==p["topic"] for j in jobs.values()):
                raise ValueError("Topic bereits vergeben.")
            inv = await self.inventory()
            root_id = "dms_"+hashlib.sha256(p["topic"].encode()).hexdigest()[:20]
            if any(mac in s["macs"] or root_id in s["identifiers"] for s in inv["sources"]):
                raise ValueError("Dieser Plug ist bereits in HA registriert.")
            job = dict(mac=mac,ip=ip,ap=ap,plan=p,step=step,error="",entity="")
            if template is not None:
                job["template"] = {"settings": template["settings"], "model": template["model"]}
                job["template_skipped"] = template["skipped"]
            jobs[mac] = job
            self.save()
            self.task = asyncio.create_task(self.run(job))
        elif action=="resume":
            job = jobs[d["mac"]]
            if job["step"]=="Fertig":
                raise ValueError("Bereits abgeschlossen.")
            await self.release_radio()
            if d.get("ip"):
                ip = local_ip(d["ip"])
                await self.identify(ip,job["mac"])
                job["ip"] = ip
                if job["step"]=="WLAN":
                    self.phase(job,"Firmware")
            self.task = asyncio.create_task(self.run(job))
        elif action in ("label","effects"):
            job = jobs[d["mac"]]
            if job["step"]!="Fertig":
                raise ValueError("Discovery zuerst abschließen.")
            if action=="effects":
                return await self.effects(d,job)
            ent = next(e for e in await self.ws("config/entity_registry/list") if e["entity_id"]==job["entity"])
            await self.ws("config/entity_registry/update",entity_id=job["entity"],
                          labels=sorted(set(ent.get("labels",[])) | {d["label"]}))
        elif action=="undo":
            b = self.db["backups"][d["key"]]
            current = await self.call(b["path"])
            if current != b["after"]:
                raise ValueError("Seit der Änderung abweichender Stand. Manuell prüfen.")
            await self.call(b["path"],b["before"])
            del self.db["backups"][d["key"]]
            self.save()
        else:
            raise ValueError("Unbekannte Aktion.")
        return {"ok":True}


def create_app(controller):
    @web.middleware
    async def ingress(request,handler):
        if request.remote != "172.30.32.2":
            raise web.HTTPForbidden()
        if request.method=="POST" and (request.content_type!="application/json" or request.headers.get("X-Onboarding")!="1"):
            raise web.HTTPForbidden()
        return await handler(request)

    app = web.Application(middlewares=[ingress])
    async def page(request):
        return web.FileResponse(Path(__file__).with_name("index.html"))
    async def api(request):
        try:
            d = await request.json()
            async with controller.lock:
                result = await controller.action(request.match_info["action"],d)
            return web.json_response(result,headers={"Cache-Control":"no-store"})
        except (ValueError,KeyError,TypeError,RuntimeError,TimeoutError,aiohttp.ClientError) as e:
            return web.json_response({"error":str(e) or type(e).__name__},status=400)
    async def ctx(app):
        controller.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=35))
        try:
            await controller.release_radio()
        except Exception as e:
            controller.notice = str(e)
        watcher = asyncio.create_task(controller.watch())
        monitor = asyncio.create_task(controller.monitor())
        try:
            yield
        finally:
            watcher.cancel()
            for task in (watcher,monitor,controller.task):
                if task:
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
            await controller.http.close()
    app.cleanup_ctx.append(ctx)
    app.router.add_get("/",page)
    app.router.add_post("/api/{action}",api)
    return app


if __name__=="__main__":
    os.umask(0o077)
    web.run_app(create_app(Assistant()),port=8099,access_log=None)
