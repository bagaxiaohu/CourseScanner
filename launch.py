from pathlib import Path
import json,sys,time,traceback
def verify(output):
    from scanner import __main__ as ui
    import tkinter as tk
    from tkinter import ttk
    from tempfile import TemporaryDirectory
    from types import SimpleNamespace
    root=None
    try:
      with TemporaryDirectory() as tmp:
        ui.enable_high_dpi()
        root=tk.Tk()
        app=ui.App(root,Path(tmp)/"data")
        assert app.bundled is not None
        def descendants(widget):
          for child in widget.winfo_children():
            yield child
            yield from descendants(child)
        button=next(x for x in descendants(root) if isinstance(x,ttk.Button) and str(x.cget("text"))=="运行无害演示")
        button.invoke()
        end=time.monotonic()+20
        while app.busy:
          assert time.monotonic()<end
          root.update();time.sleep(.02)
        root.update()
        results=list(app.results.values())
        assert len(results)==4 and app.batch_errors==0
        assert [r.display_verdict for r in results]==["签名命中","签名命中","可疑","未发现威胁"]
        assert results[0].hash_records==(('ClamAV','Eicar-Test-Signature'),)
        assert results[1].yara_matches==('Elastic/Windows_Trojan_AgentTesla_ebf431a8',)
        assert not results[2].rules and not results[2].yara_matches
        assert "文件名启发式" in results[2].details
        assert len(app.scanner.rule_sources)==5
        assert not (app.bundled/'demo-samples/01-real-signature-eicar.com').exists()
        app.show_evidence(results[1]);root.update()
        detail=next(x for x in root.winfo_children() if isinstance(x,tk.Toplevel))
        text=next(x for x in descendants(detail) if isinstance(x,tk.Text))
        assert str(text.cget('state'))=='disabled'
        assert 'Windows_Trojan_AgentTesla.yar:124' in text.get('1.0','end')
        detail.destroy()
        for lang in ('en','ru','zh'):
          app.set_language(lang);root.update()
          assert 'YARA' not in app.evidence_text(results[2])
        out={"passed":True,"results":[{"name":r.path.name,"verdict":r.display_verdict,"details":r.details} for r in results],
             "status":app.status.get(),"data_path":str(app.data),"bundled":str(app.bundled),
             "read_only_details":True,"eicar_not_written":True}
        Path(output).write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
    except BaseException:
      Path(output).write_text(traceback.format_exc(),encoding='utf8')
      raise
    finally:
      if root is not None:root.destroy()
if __name__=="__main__":
 if len(sys.argv)==3 and sys.argv[1]=="--verify-demo":
  verify(sys.argv[2])
 else:
  from scanner.__main__ import main
  main()
