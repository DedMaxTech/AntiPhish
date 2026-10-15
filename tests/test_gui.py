import os

import pytest

from antiphish.models import AnalysisReport, AnalysisStatus


@pytest.mark.skipif(os.name != "nt", reason="Windows Tk runtime")
def test_gui_worker_and_incomplete_statuses(empty_kb, monkeypatch):
    from antiphish import gui
    from antiphish.analyzer import Analyzer
    monkeypatch.setattr(gui, "Analyzer", lambda: Analyzer(empty_kb))
    app = gui.AntiPhishGui()
    app.withdraw()
    try:
        app.network.set("offline")
        app.input_text.insert("1.0", "<h1>Счёт по договору</h1><p>Реквизиты прежние</p>")
        app.run_analysis()
        finished = []
        def poll():
            if app.running:
                app.after(20, poll)
            else:
                finished.append(True)
                app.quit()
        app.after(20, poll)
        watchdog = app.after(5000, app.quit)
        app.mainloop()
        app.after_cancel(watchdog)
        assert finished and app.last_report["verdict"] == "NOT_DETECTED"
        # A real application reuses one interpreter for consecutive results.
        for status in (AnalysisStatus.PARTIAL, AnalysisStatus.FAILED):
            app.running = True
            app.analyze_button.configure(state="disabled")
            report = AnalysisReport(analysis_status=status, warnings=["Synthetic unavailable resource"])
            report.configuration.update(profile="quality", network_mode="http", network_analysis_status="PARTIAL")
            app._show(report)
            app.update_idletasks()
            assert not app.running
            assert str(app.analyze_button.cget("state")) == "normal"
            assert app.verdict.cget("bg") == "#e5e7eb"
            assert status.value in app.verdict.cget("text")
            if status == AnalysisStatus.FAILED:
                assert "NOT_DETECTED" not in app.verdict.cget("text")
            assert app.last_report["analysis_status"] == status.value
            texts = [app.tree.item(node, "text") for parent in app.tree.get_children() for node in app.tree.get_children(parent)]
            assert "Ограничение разбора" in texts
    finally:
        app.destroy()
