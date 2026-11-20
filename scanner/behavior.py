"""Read only exported Sysmon XML. No collection, subprocesses or sample execution."""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from uuid import UUID
from xml.etree import ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def analyze(raw):
    if len(raw)>4*1024*1024:
        raise ValueError("XML exceeds 4 MiB")
    text=raw.decode("utf-16" if raw.startswith((b"\xff\xfe",b"\xfe\xff")) else "utf-8-sig")
    if "<!DOCTYPE" in text or "<!ENTITY" in text or "\x00" in text:
        raise ValueError("Unsupported XML declaration or encoding")
    root=ET.fromstring(text)
    writes=defaultdict(list); starts=[]; count=0
    for event in root.iter(NS+"Event"):
        sys=event.find(NS+"System")
        if sys is None: continue
        prov=sys.find(NS+"Provider"); eid=sys.findtext(NS+"EventID")
        if prov is None or prov.get("Name")!="Microsoft-Windows-Sysmon" or eid not in ("1","11"): continue
        f={v.get("Name"):v.text or "" for v in event.findall(NS+"EventData/"+NS+"Data")}
        gid=f.get("ProcessGuid" if eid=="11" else "ParentProcessGuid","")
        path=f.get("TargetFilename" if eid=="11" else "Image","")
        host=sys.findtext(NS+"Computer","").casefold()
        try:
            guid=UUID(gid.strip("{}")); ts=datetime.fromisoformat(f["UtcTime"].replace("Z","+00:00"))
            ts=ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
        except (KeyError,ValueError): continue
        if not host or not guid.int or not PureWindowsPath(path).is_absolute(): continue
        count+=1
        key=(host,guid,str(PureWindowsPath(path)).casefold())
        rec=sys.findtext(NS+"EventRecordID","?")
        if eid=="11": writes[key].append((ts,rec))
        else: starts.append((key,ts,rec,path))
    if not count: raise ValueError("No usable Sysmon 1/11 events")
    from bisect import bisect_right
    for events in writes.values(): events.sort()
    hits=[]
    for key,ts,rec,path in sorted(starts,key=lambda x:x[1]):
        events=writes.get(key,[])
        i=bisect_right(events,(ts,chr(0x10ffff)))-1
        if i>=0 and (ts-events[i][0]).total_seconds()<=60:
            t,r=events[i]
            hits.append(f"{key[0]} | {t.isoformat()} #11/{r} -> {ts.isoformat()} #1/{rec} | {path}")
    return count,hits
