import unittest
from scanner.behavior import analyze

def trace(delay=45,host="LAB"):
    def event(i,t,h):
        g="12345678-0000-4000-8000-000000000001"
        fields={"UtcTime":f"2026-11-19 12:{t//60:02}:{t%60:02}",("ProcessGuid" if i==11 else "ParentProcessGuid"):g,("TargetFilename" if i==11 else "Image"):r"C:\Lab\editor.exe"}
        return f'<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>{i}</EventID><Computer>{h}</Computer><EventRecordID>{i+10}</EventRecordID></System><EventData>'+''.join(f'<Data Name="{k}">{v}</Data>' for k,v in fields.items())+'</EventData></Event>'
    return ('<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'+event(1,delay,host)+event(11,0,"LAB")+'</Events>').encode()

class BehaviorTests(unittest.TestCase):
    def test_pair(self): self.assertEqual(len(analyze(trace())[1]),1)
    def test_controls(self):
        for data in (trace(61),trace(host="OTHER")): self.assertEqual(analyze(data)[1],[])
    def test_bad(self):
        for data in (b'<!DOCTYPE x><x/>',b'x'*4194305,b'<Events/>'):
            with self.assertRaises(ValueError): analyze(data)
