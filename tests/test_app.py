import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"shelly_onboarding"))
from app import Assistant, AP
from logic import discovery, extend, plug, radio, local_ip, plan_fields

MAC = "aabbccddeeff"
FIXTURE=json.loads(Path(__file__).with_name("plug.json").read_text())
INFO = dict(mac=MAC.upper(),id=FIXTURE["id"],app="PlusPlugS",gen=2,model="Plug S",ver="1.5")
PLAN = dict(topic="lights/christmas-"+MAC, name="Stern",ssid="IoT",broker="broker:8883",user="plug",
            area="garten",tls="user_ca.pem",initial_state="off")
NET = {"interfaces":[dict(interface="eth0",type="ethernet",connected=True,primary=True),
                     dict(interface="wlan0",type="wireless",enabled=False,connected=False)]}


CONFIG={**FIXTURE["device_config"],"mqtt":{**FIXTURE["device_config"]["mqtt"],"topic_prefix":PLAN["topic"]}}


class Rules(unittest.TestCase):
    def test_identity(self):
        a = discovery(INFO,PLAN,"homeassistant",CONFIG,"192.168.1.5")
        b = discovery(INFO,{**PLAN,"name":"Renamed"},"homeassistant",CONFIG,"192.168.1.5")
        self.assertEqual([m["topic"] for m in a[0]], [m["topic"] for m in b[0]])
        self.assertGreater(len(a[0]),1)
        self.assertEqual(a[1],b[1])
        with self.assertRaises(ValueError):
            plug({**INFO,"app":"Plus2PM"})

    def test_network(self):
        self.assertEqual(radio(NET,"wlan0")["interface"],"wlan0")
        with self.assertRaises(ValueError):
            radio({"interfaces":[NET["interfaces"][1]]},"wlan0")
        for bad in ("8.8.8.8","127.0.0.1","host:8080","::1"):
            with self.assertRaises(ValueError):
                local_ip(bad)

    def test_actions(self):
        source = {"triggers":[{"entity_id":"switch.a"}],"actions":[{"choose":[{"sequence":[
            {"action":"switch.turn_on","target":{"entity_id":"switch.a"}}]}]}]}
        updated, changes = extend(source,"switch.a","switch.b")
        self.assertEqual(len(changes),1)
        self.assertEqual(updated["triggers"],source["triggers"])
        self.assertNotIn("switch.b",str(source))
        self.assertFalse(extend(updated,"switch.a","switch.b")[1])

    def test_validation(self):
        self.assertEqual(plan_fields(PLAN),PLAN)
        with self.assertRaises(ValueError):
            plan_fields({**PLAN,"topic":"#"})


class Workflow(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        opts = dict(wifi_interface="wlan0",wifi_password="wifi-secret",mqtt_password="mqtt-secret",
                    ca_pem="certificate",discovery_prefix="homeassistant")
        (self.root/"options.json").write_text(json.dumps(opts))
        with patch.dict(os.environ,SUPERVISOR_TOKEN="mock"):
            self.app = Assistant(self.root)
        self.job = dict(mac=MAC,ap=INFO["id"],ip=None,step="WLAN",error="",entity="",plan=PLAN)
        self.app.db["jobs"][MAC] = self.job
        self.app.ws = AsyncMock(return_value=[dict(platform="mqtt",unique_id=discovery(INFO,PLAN,"homeassistant",CONFIG,"192.168.1.5")[1],
                                                  device_id="test",entity_id="switch.stern")])
        self.app.service = AsyncMock()

    async def test_first_setup(self):
        async def rpc(ip,method,params=None):
            if method=="Shelly.GetDeviceInfo":
                return INFO
            if method=="WiFi.GetStatus":
                return dict(sta_ip="192.168.10.5",ssid="IoT")
            if method=="Shelly.GetConfig":
                return CONFIG
            if method=="MQTT.GetStatus":
                return dict(connected=True)
            return {}
        async def call(path,body=None):
            if path=="network/info":
                return NET
            if path.startswith("core/api/states"):
                return {"state":"off"}
            return {}
        self.app.rpc=AsyncMock(side_effect=rpc)
        self.app.call=AsyncMock(side_effect=call)
        with patch("app.asyncio.sleep",new=AsyncMock()):
            await self.app.run(self.job)
        self.assertEqual(self.job["step"],"Fertig",self.job["error"])
        self.assertEqual(self.job["ip"],"192.168.10.5")
        self.assertNotIn("lease",self.app.db)
        self.assertNotIn("secret",self.app.path.read_text())
        self.assertEqual(self.app.service.await_count,self.job["entities_published"]+3)

    async def test_wrong_plug(self):
        self.app.rpc=AsyncMock(return_value={**INFO,"mac":"112233445566"})
        self.app.call=AsyncMock(return_value=NET)
        with patch("app.asyncio.sleep",new=AsyncMock()):
            await self.app.run(self.job)
        self.assertTrue(self.job["error"])
        self.assertNotIn("lease",self.app.db)
        self.assertTrue(all(args.args[1]=="Shelly.GetDeviceInfo" for args in self.app.rpc.await_args_list))

    async def test_installs_all_stable_firmware_before_mqtt(self):
        self.job.update(step="Firmware", ip="192.168.1.12")
        versions = iter(["1.6", "1.7", None])
        installed = INFO["ver"]
        target = None
        methods = []

        async def rpc(ip, method, params=None):
            nonlocal installed, target
            methods.append(method)
            if method == "Shelly.GetDeviceInfo":
                return {**INFO, "ver": installed}
            if method == "Shelly.GetConfig":
                return CONFIG
            if method == "Shelly.CheckForUpdate":
                target = next(versions)
                return {"stable": {"version": target}} if target else {"beta": {"version": "2.0"}}
            if method == "Shelly.Update":
                installed = target
            if method == "MQTT.GetStatus":
                return {"connected": True}
            return {}

        self.app.rpc = AsyncMock(side_effect=rpc)
        self.app.call = AsyncMock(return_value={"state": "off"})
        with patch("app.asyncio.sleep", new=AsyncMock()):
            await self.app.run(self.job)

        self.assertEqual(self.job["step"], "Fertig", self.job["error"])
        self.assertEqual(installed, "1.7")
        before_mqtt = methods[:methods.index("MQTT.SetConfig")]
        self.assertEqual(before_mqtt.count("Shelly.CheckForUpdate"), 3)
        self.assertEqual(before_mqtt.count("Shelly.Update"), 2)

    async def test_bulk_effects_preflight_and_individual_undo(self):
        old, new = "switch.reference", "switch.stern"
        self.job.update(step="Fertig", entity=new)
        self.app.inventory = AsyncMock(return_value={"sources": [{"id": "reference", "switches": [old]}]})
        automation = "core/api/config/automation/config/123"
        script = "core/api/config/script/config/light_off"
        configs = {
            automation: {"actions": [{"action": "switch.turn_on", "target": {"entity_id": old}}]},
            script: {"sequence": [{"action": "switch.turn_off", "target": {"entity_id": old}}]},
        }
        original = configs.copy()

        async def call(path, body=None):
            if path == "core/api/states":
                return [
                    {"entity_id": "automation.light_on", "attributes": {"id": "123"}},
                    {"entity_id": "script.light_off", "attributes": {}},
                ]
            if body is not None:
                configs[path] = body
            return configs[path]

        self.app.call = AsyncMock(side_effect=call)
        request = {"mac": MAC, "old": old}
        preview = await self.app.action("effects", request)
        apply_all = {ref["path"]: ref["digest"] for ref in preview["refs"]}
        with self.assertRaisesRegex(ValueError, "Vorschau veraltet"):
            await self.app.action("effects", {**request, "apply_all": {**apply_all, script: "stale"}})
        self.assertEqual(configs, original)

        result = await self.app.action("effects", {**request, "apply_all": apply_all})
        self.assertEqual(result, {"saved": ["automation.light_on", "script.light_off"], "failed": []})
        self.assertTrue(all(new in str(config) for config in configs.values()))
        await self.app.action("undo", {"key": MAC + ":script.light_off"})
        self.assertEqual(configs[script], original[script])
        self.assertIn(new, str(configs[automation]))

    async def test_discovery_retry(self):
        self.job.update(step="Discovery",ip="192.168.1.12")
        self.app.rpc=AsyncMock(side_effect=lambda ip,method,*args: CONFIG if method=="Shelly.GetConfig" else INFO)
        self.app.call=AsyncMock(return_value={"state":"unknown"})
        with patch("app.asyncio.sleep",new=AsyncMock()):
            await self.app.run(self.job)
            self.assertEqual(self.job["step"],"Discovery")
            self.app.call.return_value={"state":"on"}
            await self.app.run(self.job)
        self.assertEqual(self.job["step"],"Fertig")
        self.assertTrue(all(args.args[1] in ("Shelly.GetDeviceInfo","Shelly.GetConfig","Shelly.GetStatus","WiFi.SetConfig") for args in self.app.rpc.await_args_list))


if __name__=="__main__":
    unittest.main()
