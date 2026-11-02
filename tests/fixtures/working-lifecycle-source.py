"""Fake-only lifecycle/TTY/profile tests. Never Docker, sockets, login or model."""
import copy
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import threading
import unittest
from unittest.mock import patch


import auth
import controller
import core
import relay
import spec
import validate
import work_a as work
import ready_channel


def hello(host):
    name = host.encode()
    value = struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name
    extensions = b"\0\0" + struct.pack("!H", len(value)) + value
    body = b"\x03\x03" + bytes(32) + b"\0\0\2\x13\x01\1\0" + struct.pack("!H", len(extensions)) + extensions
    handshake = b"\1" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def network_fixture(role):
    subnet = spec.INTERNAL if role == "internal" else spec.EXTERNAL
    return {"Id": ("a" if role == "internal" else "b") * 64, "Name": spec.NETWORKS[role],
        "Labels": spec.LABELS.copy(), "Driver": "bridge", "Scope": "local", "Internal": role == "internal",
        "EnableIPv4":True,"Attachable":False,"EnableIPv6": False, "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"} if role == "internal" else {},
        "IPAM": {"Driver": "default", "Config": [{"Subnet": subnet} if role=="internal" else {"Subnet":subnet,"Gateway":"10.253.251.1"}]}, "Containers": {}}


def volume_fixture():
    return {"Name": spec.VOLUME, "Driver": "local", "Scope": "local", "Labels": spec.LABELS.copy(), "Options": spec.VOLUME_OPTIONS.copy()}


def container_fixture(role):
    args = spec.create(role, "a" * 64)
    source = next(args[i + 1] for i, v in enumerate(args) if v == "--mount" and args[i + 1].startswith("type=bind,")).split("src=", 1)[1].split(",dst=", 1)[0]
    hosts = spec.HOSTS if role == "auth" else spec.WORK_HOSTS if role in {"work_a","work_b"} else ()
    result = {"Id": {"relay": "c", "auth": "d", "work_a": "e", "work_b": "f"}[role] * 64, "Name": "/" + spec.CONTAINERS[role], "Image": spec.IMAGE,
        "EnvExact":True,"Config": {"Labels": spec.LABELS | {"cas.series1.role": role}, "User": "10001:10001", "Entrypoint": ["python"], "Cmd": ["-I", "-B", "/cas-sub7.py"], "WorkingDir": "/var/lib/cas", "StopTimeout": 5,"StopSignal":"SIGTERM","Healthcheck":{"Test":["NONE"]},
            "Env": spec.load("image-env.json") + ["CAS_PHASE1_ACTIVATION=one-approved-personal-subscription-two-stage-series"], "Tty": role == "auth", "OpenStdin": role != "relay"},
        "State": {"Status": "created", "Running": False, "Pid": 0, "ExitCode": 0, "OOMKilled": False, "Error": ""},
        "HostConfig": {"Init":False,"ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"], "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private", "NetworkMode": "a" * 64,
            "Dns": ["1.1.1.1"] if role == "relay" else ["127.0.0.1"], "ExtraHosts": [host + ":" + spec.RELAY_IP for host in hosts],
            "Memory": 1073741824, "MemorySwap": 1073741824, "NanoCpus": 1000000000, "PidsLimit": 64, "ShmSize": 67108864, "Runtime": "runc", "AutoRemove": False, "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none", "Config": {}},
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=128m,mode=1777", "/var/lib/cas": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700"} | ({"/home/cas": "rw,nosuid,nodev,noexec,size=64m,uid=10001,gid=10001,mode=0700"} if role == "relay" else {}),
            "Ulimits": [{"Name": key, "Soft": value, "Hard": value} for key, value in [("core", 0), ("nofile", 256), ("fsize", 16777216)]],
            "Mounts": [] if role == "relay" else [{"Type": "volume", "Source": spec.VOLUME, "Target": "/home/cas", "VolumeOptions": {"NoCopy": True}}]},
        "Mounts": [{"Type": "bind", "Source": source, "Destination": "/cas-sub7.py", "RW": False}],
        "NetworkSettings": {"Networks": {spec.NETWORKS["internal"]: {"NetworkID": "a" * 64, "IPAddress": spec.IP[role], "IPAMConfig": {"IPv4Address": spec.IP[role]}}}}}
    if role=="auth":result["Mounts"].append({"Type":"bind","Source":str((spec.ROOT/"ready_wire.py").resolve()),"Destination":"/cas-ready-wire.py","RW":False})
    if role != "relay": result["Mounts"].append({"Type": "volume", "Name": spec.VOLUME, "Destination": "/home/cas", "RW": True})
    return result


class Clock:
    def __init__(self): self.value = 0
    def __call__(self): return self.value
    def sleep(self, seconds): self.value += seconds


class Pipe:
    def __init__(self, fake=None): self.fake = fake
    def close(self): pass
    def write(self, value):
        if self.fake is not None:
            if value != b"GO\n": raise AssertionError("Credentials/other input forbidden")
            self.fake.go_count += 1


class FakeJob:
    def __init__(self, fake, role, mode):
        self.fake, self.role, self.mode, self.overflow = fake, role, mode, False
        self.process = type("Process", (), {"stdin": Pipe(fake)})()
    def output(self):
        if self.role=="relay" and not getattr(self,"relay_ready_sent",False):
            self.fake.advance(self.role)
            if not self.fake.objects["container"][spec.CONTAINERS[self.role]]["State"]["Running"]:return b"",b""
            self.relay_ready_sent=True
        return (json.dumps({"scope": "cas-series-1-relay", "status": "READY", "port": 443,
            "addresses": {host: "1.1.1.1" for host in spec.HOSTS}}).encode() + b"\n", b"")
    def poll(self):
        doc = self.fake.objects["container"].get(spec.CONTAINERS[self.role])
        return None if doc is not None and (doc["State"]["Running"] or self.role in self.fake.pending_start) else 0


class FakeDocker:
    def __init__(self, clock):
        self.clock, self.calls = clock, []
        self.number=0;self.active_work="work_a";self.events=[];self.pending_start={};self.observed_work_states=[]
        self.objects = {"container": {}, "network": {}, "volume": {}}
        self.cancelled, self.ignore_cancel = threading.Event(), False
        self.go_count, self.private_count = 0, 0
        self.fail_mutation = None
        self.marker = ready_channel.TOKEN
        self.early_holder_exit = False
        self.bad_subscription = False
        self.bad_work_network = False
        self.repeat_cancel = False
        self.jobs = []
        self.logout_ack = False
        self.work_stop_unconfirmed = False
        self.holder_dies_during_work = False
        self.late_budget_loss = False
    def budget(self,args):
        if self.number >= (112 if self.ignore_cancel else 72):raise core.Failure('operation-budget')
        if not self.ignore_cancel and self.number+1+getattr(self,'cleanup_reserve',lambda:0)()>112:
            self.reserve_failure=dict(number=self.number,reserve=self.cleanup_reserve(),operation=args[:2]);raise core.Failure('CLEANUP_OPERATION_RESERVE')
        if self.cancelled.is_set() and not self.ignore_cancel:raise core.Failure('cancelled')
        self.number+=1
    def advance(self,role):
        if role not in self.pending_start:return
        self.pending_start[role]-=1
        if self.pending_start[role]<=0:
            self.pending_start.pop(role)
            doc=self.objects["container"][spec.CONTAINERS[role]];doc["State"].update(Status="running",Running=True,Pid=50)
            for e in doc["NetworkSettings"]["Networks"].values():e["IPAddress"]=(e.get("IPAMConfig") or {}).get("IPv4Address","")
            for network in self.objects['network'].values():
                if network['Id'] in {v['NetworkID'] for v in doc['NetworkSettings']['Networks'].values()}:network['Containers'][doc['Id']]={'Name':spec.CONTAINERS[role]}
    def result(self, obj=b"", rc=0, err=b""):
        return {"rc": rc, "out": obj if isinstance(obj, bytes) else json.dumps(obj).encode(), "err": err, "failure": None, "elapsed": 0}
    def find(self, kind, target):
        return next((v for k, v in self.objects[kind].items() if target in {k, v.get("Id", k)}), None)
    def run(self, args, seconds=5):
        self.clock.value += 0.01
        self.budget(args);self.calls.append(args)
        if self.ignore_cancel and self.repeat_cancel: self.cancelled.set()
        if args[1:2] == ["inspect"]:
            if args[0] == "volume" and self.late_budget_loss and self.objects["container"].get(spec.CONTAINERS[getattr(self,"active_work","work_a")], {}).get("State", {}).get("Running"):
                self.clock.value += 370
                self.late_budget_loss = False
            doc = self.find(args[0], args[-1])
            if doc is None: return self.result(rc=1, err=("Error: No such object: " + args[-1]).encode())
            if args[0]=="container":
                role=doc["Config"]["Labels"]["cas.series1.role"]
                if role in self.pending_start:
                    snapshot=copy.deepcopy(doc);self.advance(role);doc=snapshot
                if role in {"work_a","work_b"}:self.observed_work_states.append(doc["State"]["Status"])
            if self.bad_work_network and doc.get("Config", {}).get("Labels", {}).get("cas.series1.role") in {"work_a","work_b"} and doc["State"]["Running"]:
                doc = copy.deepcopy(doc)
                doc["NetworkSettings"]["Networks"]["foreign"] = {"NetworkID": "f" * 64, "IPAddress": "8.8.8.8"}
            return self.result([doc])
        if args[:2] == ["volume", "create"]: self.objects["volume"][spec.VOLUME] = volume_fixture()
        elif args[:2] == ["network", "create"]:
            role = "internal" if args[-1] == spec.NETWORKS["internal"] else "external"
            self.objects["network"][spec.NETWORKS[role]] = network_fixture(role)
        elif args[0] == "create":
            name = args[args.index("--name") + 1]
            role = next(r for r, n in spec.CONTAINERS.items() if n == name)
            if role=="work_b":
                assert spec.CONTAINERS["work_a"] not in self.objects["container"],"A must be removed BEFORE B create"
            self.objects["container"][name] = container_fixture(role)
        elif args[:2] == ["network", "connect"]:
            self.find("container", args[-1])["NetworkSettings"]["Networks"][spec.NETWORKS["external"]] = {"NetworkID": "b" * 64, "IPAddress": "10.253.251.2", "IPAMConfig": {"IPv4Address": "10.253.251.2"}}
        elif args[0] == "cp": raise AssertionError("cp forbidden")
        elif args[0] in {"stop", "kill"}:
            doc = self.find("container", args[-1])
            if "--signal" in args:
                self.logout_ack = True
                return self.result()
            if self.work_stop_unconfirmed and doc["Config"]["Labels"]["cas.series1.role"] in {"work_a","work_b"}:
                return self.result(rc=1, err=b"stop not confirmed")
            doc["State"].update(Status="exited", Running=False, Pid=0)
            if doc["Config"]["Labels"]["cas.series1.role"] == "auth" and not self.logout_ack: doc["State"]["ExitCode"] = 1
        elif args[0] == "rm":
            doc = self.find("container", args[1]); self.pending_start.pop(doc["Config"]["Labels"]["cas.series1.role"],None);self.objects["container"].pop(doc["Name"].lstrip("/"))
            for network in self.objects['network'].values():network['Containers'].pop(doc['Id'],None)
        elif args[0] in {"network", "volume"} and args[1] == "rm":
            doc = self.find(args[0], args[-1]); self.objects[args[0]].pop(doc["Name"])
        if self.fail_mutation and self.fail_mutation(args):
            self.fail_mutation = None
            raise core.Failure("uncertain-create")
        if args[0]=="create":return self.result((self.find("container",args[args.index("--name")+1])["Id"]+"\n").encode())
        if args[:2]==["network","create"]:return self.result((self.find("network",args[-1])["Id"]+"\n").encode())
        return self.result()
    def start(self, args, mode):
        self.budget(args);self.calls.append(args)
        doc = self.find("container", args[-1])
        if args[0] == "start":
            role=doc["Config"]["Labels"]["cas.series1.role"];self.pending_start[role]=2
            if role in {"work_a","work_b"}:self.active_work=role
            for e in doc["NetworkSettings"]["Networks"].values():e["IPAddress"]=""
        role = doc["Config"]["Labels"]["cas.series1.role"]
        job = FakeJob(self, role, mode); self.jobs.append(job)
        return job
    def launch(self,args):
        if args[0]=="exec":
            self.budget(args);self.calls.append(args);return FakeJob(self,"auth","exec")
        return self.start(args,"wait" if args[0]=="wait" else "capture")
    def private(self, args):
        self.private_count += 1
        return self.start(args, "private")
    def finish(self, job, seconds, guard=lambda: True):
        if job.role in {"work_a","work_b"} and self.holder_dies_during_work:
            self.objects["container"][spec.CONTAINERS["auth"]]["State"].update(Status="exited", Running=False, Pid=0, ExitCode=1)
        if not guard(): raise core.Failure("holder-or-relay-failed")
        if job.mode=="exec":
            result=ready_channel.sanitize(self.result(self.marker))
            if result["failure"]:raise core.Failure(result["failure"])
            return result
        if job.mode == "private":
            while job.role in self.pending_start:self.advance(job.role)
            if self.early_holder_exit: self.objects["container"][spec.CONTAINERS["auth"]]["State"].update(Status="exited", Running=False, Pid=0)
            return self.result()
        if job.mode == "wait": return self.result(b"0\n")
        if job.role in {"work_a","work_b"}:
            self.objects["container"][spec.CONTAINERS[getattr(self,"active_work","work_a")]]["State"].update(Status="exited", Running=False, Pid=0)
            for endpoint in self.objects["container"][spec.CONTAINERS[getattr(self,"active_work","work_a")]]["NetworkSettings"]["Networks"].values(): endpoint["IPAddress"] = ""
            return self.result({"scope": "cas-sub7-one-subscription-baseline", "result": "FAIL" if self.bad_subscription else "PASS", "marker_and_native_success": True,
                "tree_empty": True, "mechanism": "linux-pid-namespace", "auth_mode": "subscription", "api_fallback": False})
        return self.result(job.output()[0])
    def sweep(self, seconds): return []
