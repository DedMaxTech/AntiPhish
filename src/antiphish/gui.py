from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .analyzer import Analyzer


class AntiPhishGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AntiPhish - локальный анализ")
        self.geometry("1040x720")
        self.minsize(800, 560)
        self.analyzer = Analyzer()
        self.path = tk.StringVar()
        self.network = tk.StringVar(value="offline")
        self.profile = tk.StringVar(value="quality")
        self.status = tk.StringVar(value="Готов")
        self.mode_hint = tk.StringVar()
        self.last_report = None
        self._build()

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Файл / URL:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Выбрать файл", command=self.choose_file).grid(row=0, column=2)
        ttk.Label(top, text="Сеть:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Combobox(top, textvariable=self.network, values=("offline", "http", "browser"), state="readonly", width=12).grid(row=1, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(top, text="Профиль:").grid(row=1, column=1, sticky="e", padx=(0, 180), pady=(8, 0))
        ttk.Combobox(top, textvariable=self.profile, values=("fast", "quality", "deep"), state="readonly", width=12).grid(row=1, column=1, sticky="e", padx=6, pady=(8, 0))
        ttk.Button(top, text="Анализировать", command=self.run_analysis).grid(row=1, column=2, pady=(8, 0))
        ttk.Label(top, textvariable=self.mode_hint, foreground="#374151", wraplength=900).grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        top.columnconfigure(1, weight=1)
        self.profile.trace_add("write", self._update_mode_hint)
        self.network.trace_add("write", self._update_mode_hint)
        self._update_mode_hint()

        ttk.Label(self, text="Или вставьте raw MIME / HTML:").pack(anchor="w", padx=10)
        self.input_text = tk.Text(self, height=9, wrap="word")
        self.input_text.pack(fill="x", padx=10, pady=(2, 8))
        self.verdict = tk.Label(self, text="-", font=("Segoe UI", 20, "bold"), bg="#e5e7eb", pady=10)
        self.verdict.pack(fill="x", padx=10)
        self.tree = ttk.Treeview(self, columns=("value",), show="tree headings")
        self.tree.heading("#0", text="Раздел")
        self.tree.heading("value", text="Доказательство")
        self.tree.column("#0", width=250)
        self.tree.pack(fill="both", expand=True, padx=10, pady=8)
        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")
        ttk.Label(bottom, textvariable=self.status).pack(side="left")
        ttk.Button(bottom, text="Сохранить JSON", command=self.save_json).pack(side="right")

    def _update_mode_hint(self, *_):
        profiles = {
            "fast": "Fast: сокращённые лимиты, без QR и изображений внутри PDF.",
            "quality": "Quality: полный статический разбор, QR и изображения документов.",
            "deep": "Deep: Quality + локальные Qwen/SigLIP; модель сама не блокирует.",
        }
        networks = {
            "offline": "Offline: ссылки не открываются.",
            "http": "HTTP: до 5 извлечённых ссылок загружаются безопасным GET без JavaScript.",
            "browser": "Browser: до 2 ссылок открываются в изолированном Edge с JavaScript.",
        }
        self.mode_hint.set(f"{profiles[self.profile.get()]} {networks[self.network.get()]}")

    def choose_file(self):
        value = filedialog.askopenfilename(title="Выберите письмо или документ", filetypes=[("Поддерживаемые", "*.eml *.html *.htm *.pdf *.doc *.docx *.docm *.xls *.xlsx *.xlsm *.ppt *.pptx *.pptm *.png *.jpg *.jpeg"), ("Все файлы", "*.*")])
        if value:
            self.path.set(value)

    def run_analysis(self):
        source_text = self.input_text.get("1.0", "end-1c")
        source = self.path.get().strip() or source_text.encode("utf-8")
        if not source:
            messagebox.showinfo("AntiPhish", "Выберите файл, укажите URL или вставьте письмо/HTML")
            return
        confirmation = None
        if self.network.get() == "browser":
            if not messagebox.askyesno("Активный режим", "Browser-режим выполнит JavaScript удалённой страницы в изолированном временном контексте Edge. Продолжить?"):
                return
            confirmation = "I_UNDERSTAND"
        # Tk variables are read on the UI thread; the worker receives plain
        # strings and only schedules its result back through ``after``.
        profile = self.profile.get()
        network = self.network.get()
        self.status.set("Анализ…")
        threading.Thread(target=self._worker, args=(source, confirmation, profile, network), daemon=True).start()

    def _worker(self, source, confirmation, profile, network):
        name = "pasted.html" if isinstance(source, bytes) and b"<html" in source[:500].lower() else "pasted.eml"
        report = self.analyzer.analyze(source, name=name, profile=profile, network=network, browser_confirmation=confirmation)
        self.after(0, lambda: self._show(report))

    def _show(self, report):
        self.last_report = report.to_dict()
        colors = {"PHISHING": "#fecaca", "SUSPICIOUS": "#fde68a", "NOT_DETECTED": "#bbf7d0"}
        self.verdict.configure(text=f"{report.verdict.value} · {report.analysis_status.value}", bg=colors[report.verdict.value])
        for item in self.tree.get_children():
            self.tree.delete(item)
        config = self.tree.insert("", "end", text="Режим анализа", values=(report.configuration.get("profile_note", ""),), open=True)
        self.tree.insert(config, "end", text=f"Профиль: {report.configuration.get('profile')}", values=(", ".join(report.configuration.get("stages", [])),))
        network_value = f"{report.configuration.get('network_scope', '')}; статус: {report.configuration.get('network_analysis_status', '')}"
        self.tree.insert(config, "end", text=f"Сеть: {report.configuration.get('network_mode')}", values=(network_value,))
        if "network_urls_total" in report.configuration:
            selection = (
                f"всего URL: {report.configuration.get('network_urls_total', 0)}; "
                f"кандидатов: {report.configuration.get('network_candidates', 0)}; "
                f"ресурсов пропущено: {report.configuration.get('network_ignored_resources', 0)}"
            )
            self.tree.insert(config, "end", text="Отбор ссылок", values=(selection,))
        for activity in report.network_activity:
            details = activity.get("url", "")
            if activity.get("http_status"):
                details += f"; HTTP {activity['http_status']}"
            if activity.get("error"):
                details += f"; {activity['error']}"
            self.tree.insert(config, "end", text=activity.get("status", "NETWORK"), values=(details,))
        for warning in report.network_warnings:
            self.tree.insert(config, "end", text="Сетевая ошибка", values=(warning,))
        reasons = self.tree.insert("", "end", text="Причины", values=(len(report.reason_codes),), open=True)
        for e in report.reason_codes:
            self.tree.insert(reasons, "end", text=e.code, values=(e.summary,))
        urls = self.tree.insert("", "end", text="URL", values=(len(report.urls),), open=True)
        for u in report.urls:
            self.tree.insert(urls, "end", text=u.host or "URL", values=(f"{u.original} [{u.source or 'unknown'}]",))
        attachments = self.tree.insert("", "end", text="Вложения", values=(len(report.attachments),))
        for a in report.attachments:
            self.tree.insert(attachments, "end", text=a.name, values=(f"{a.media_type}; {a.size} bytes; {a.status}",))
        models = self.tree.insert("", "end", text="Локальные модели", values=(len(report.model_evidence),), open=bool(report.model_evidence or report.model_warnings))
        for item in report.model_evidence:
            structured = item.get("structured_extract")
            if structured:
                flags = ", ".join(
                    f"{key}={str(bool(structured.get(key))).lower()}"
                    for key in ("credential_request", "payment_change", "impersonation")
                )
                value = f"{flags}; {structured.get('rationale', '')}; {item.get('runtime_ms', 0)} мс"
            elif "brand_candidates" in item:
                candidates = item.get("brand_candidates") or []
                value = f"кандидаты: {json.dumps(candidates, ensure_ascii=False)}; порог: {item.get('acceptance_threshold')}"
            else:
                value = str(item.get("parse_status", "нет результата"))
            self.tree.insert(models, "end", text=item.get("model", "model"), values=(value,))
        for warning in report.model_warnings:
            self.tree.insert(models, "end", text="Модель не выполнена", values=(warning,))
        if not report.model_evidence and not report.model_warnings:
            message = "выберите профиль deep" if report.configuration.get("profile") != "deep" else "модель не вернула данных"
            self.tree.insert(models, "end", text="Не запускались", values=(message,))
        self.status.set(
            f"Готово за {report.timings_ms.get('total', 0)} мс · {report.configuration.get('profile')} · "
            f"{report.configuration.get('network_mode')} ({report.configuration.get('network_analysis_status')}) · "
            ""
        )

    def save_json(self):
        if not self.last_report:
            messagebox.showinfo("AntiPhish", "Сначала выполните анализ")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            Path(path).write_text(json.dumps(self.last_report, ensure_ascii=False, indent=2), encoding="utf-8")


def run_gui():
    AntiPhishGui().mainloop()
