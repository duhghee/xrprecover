#!/usr/bin/env python3
"""
BTCRecover Tokenlist Creator GUI

Creates tokenlist.txt files using:
- fixed-position tokens: ^POSITION^word
- unanchored candidate-set lines (assigned to the next unfilled position by XRPRecover)
- custom word sets
- words selected by length from a one-word-per-line wordlist

This GUI does not perform wallet recovery itself; it only creates tokenlist.txt.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import json
import math

APP_TITLE = "BTCRecover Tokenlist Creator"
ROWS = 12

class TokenlistGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1120x720")
        self.minsize(980, 620)

        self.wordlist_path = tk.StringVar(value="english.txt")
        self.status = tk.StringVar(value="Ready")
        self.rows = []

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=APP_TITLE, font=("TkDefaultFont", 16, "bold")).grid(
            row=0, column=0, columnspan=5, sticky="w", pady=(0, 8)
        )

        ttk.Label(top, text="Wordlist:").grid(row=1, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.wordlist_path, width=70).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=6
        )
        ttk.Button(top, text="Browse…", command=self.browse_wordlist).grid(row=1, column=3, padx=4)
        ttk.Button(top, text="Reload", command=self.update_counts).grid(row=1, column=4, padx=4)
        top.columnconfigure(1, weight=1)

        help_text = (
            "Fixed = anchored as ^position^token.  Permute = emitted as an unanchored candidate-set line.  "
            "XRPRecover permutes unanchored candidate-set lines ONLY among positions that have no fixed candidates.  "
            "For each row choose a single word, custom words, all wordlist words, or words of a selected length."
        )
        ttk.Label(top, text=help_text, wraplength=1050).grid(
            row=2, column=0, columnspan=5, sticky="w", pady=(8, 0)
        )

        table_outer = ttk.Frame(self, padding=(10, 0, 10, 0))
        table_outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(table_outer, highlightthickness=0)
        scrollbar = ttk.Scrollbar(table_outer, orient="vertical", command=canvas.yview)
        self.table = ttk.Frame(canvas)
        self.table.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.table, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        headers = ["Pos", "Behavior", "Source", "Value / custom words", "Length", "Candidates"]
        widths = [5, 14, 20, 50, 9, 12]
        for c, (h, w) in enumerate(zip(headers, widths)):
            ttk.Label(self.table, text=h, font=("TkDefaultFont", 10, "bold"), width=w).grid(
                row=0, column=c, padx=3, pady=4, sticky="w"
            )

        for pos in range(1, ROWS + 1):
            behavior = tk.StringVar(value="Fixed")
            source = tk.StringVar(value="Single word")
            value = tk.StringVar(value="")
            length = tk.StringVar(value="5")
            count = tk.StringVar(value="0")

            ttk.Label(self.table, text=str(pos), width=5).grid(row=pos, column=0, padx=3, pady=3)

            behavior_box = ttk.Combobox(
                self.table, textvariable=behavior, values=["Fixed", "Permute"],
                state="readonly", width=12
            )
            behavior_box.grid(row=pos, column=1, padx=3, pady=3, sticky="ew")

            source_box = ttk.Combobox(
                self.table, textvariable=source,
                values=["Single word", "Custom words", "Words by length", "All wordlist words"],
                state="readonly", width=18
            )
            source_box.grid(row=pos, column=2, padx=3, pady=3, sticky="ew")

            value_entry = ttk.Entry(self.table, textvariable=value, width=48)
            value_entry.grid(row=pos, column=3, padx=3, pady=3, sticky="ew")

            length_box = ttk.Combobox(
                self.table, textvariable=length,
                values=[str(i) for i in range(3, 9)], state="disabled", width=7
            )
            length_box.grid(row=pos, column=4, padx=3, pady=3)

            ttk.Label(self.table, textvariable=count, width=12).grid(
                row=pos, column=5, padx=3, pady=3, sticky="e"
            )

            row = {
                "behavior": behavior, "source": source, "value": value,
                "length": length, "count": count, "length_box": length_box
            }
            self.rows.append(row)

            source.trace_add(
                "write",
                lambda *_, r=row: self.after_idle(lambda: self.update_length_state(r))
            )
            for var in (behavior, source, value, length):
                var.trace_add("write", lambda *_: self.after_idle(self.update_counts))

        self.table.columnconfigure(3, weight=1)

        defaults = ["", "", "", "", "", "", "", "", "", "", "",]   
        for i, val in enumerate(defaults):
            self.rows[i]["value"].set(val)
        for i in range(6):
            self.rows[i]["behavior"].set("Fixed")
            self.rows[i]["source"].set("Single word")
        self.rows[6]["behavior"].set("Permute")
        self.rows[6]["source"].set("Single word")
        self.rows[7]["behavior"].set("Permute")
        self.rows[7]["source"].set("Custom words")
        self.rows[8]["behavior"].set("Permute")
        self.rows[8]["source"].set("Custom words")
        for i in (9, 10, 11):
            self.rows[i]["behavior"].set("Permute")
            self.rows[i]["source"].set("Words by length")
            self.rows[i]["length"].set("5")

        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill="x")

        ttk.Button(bottom, text="Clear All", command=self.clear_all).pack(side="left", padx=3)
        ttk.Button(bottom, text="Load Template…", command=self.load_template).pack(side="left", padx=3)
        ttk.Button(bottom, text="Save Template…", command=self.save_template).pack(side="left", padx=3)
        ttk.Button(bottom, text="Preview", command=self.preview).pack(side="left", padx=12)
        ttk.Button(bottom, text="Generate tokenlist.txt", command=self.generate).pack(side="left", padx=3)

        ttk.Label(bottom, textvariable=self.status).pack(side="right", padx=6)
        for row in self.rows:
            self.update_length_state(row)
        self.update_counts()

    def update_length_state(self, row):
        if row["source"].get() == "Words by length":
            row["length_box"].configure(state="readonly")
        else:
            row["length_box"].configure(state="disabled")

    def browse_wordlist(self):
        path = filedialog.askopenfilename(
            title="Select wordlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.wordlist_path.set(path)
            self.update_counts()

    def read_wordlist(self):
        path = Path(self.wordlist_path.get()).expanduser()
        if not path.is_file():
            return []
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return [line.strip() for line in f if line.strip()]

    def tokens_for_row(self, row, wordlist=None):
        source = row["source"].get()
        raw = row["value"].get().strip()

        if source == "Single word":
            return [raw] if raw else []
        if source == "Custom words":
            return raw.split() if raw else []

        if wordlist is None:
            wordlist = self.read_wordlist()

        if source == "All wordlist words":
            return wordlist
        if source == "Words by length":
            try:
                n = int(row["length"].get())
            except ValueError:
                return []
            return [w for w in wordlist if len(w) == n]
        return []

    def update_counts(self):
        try:
            wl = self.read_wordlist()
            counts = []
            for row in self.rows:
                n = len(self.tokens_for_row(row, wl))
                row["count"].set(f"{n:,}")
                counts.append(n)

            fixed = [counts[i] for i, r in enumerate(self.rows) if r["behavior"].get() == "Fixed" and counts[i]]
            perm = [counts[i] for i, r in enumerate(self.rows) if r["behavior"].get() == "Permute" and counts[i]]
            self.status.set(
                f"Wordlist: {len(wl):,} words   |   configured candidates: {sum(counts):,}   |   "
                f"fixed rows: {len(fixed)}   permuting rows: {len(perm)}"
            )
        except Exception as e:
            self.status.set(f"Error: {e}")

    def build_text(self):
        wl = self.read_wordlist()
        lines = []
        for pos, row in enumerate(self.rows, start=1):
            tokens = self.tokens_for_row(row, wl)
            if not tokens:
                continue

            if row["behavior"].get() == "Fixed":
                anchored = [f"^{pos}^{w}" for w in tokens]
                lines.append(" ".join(anchored))
            else:
                lines.append(" ".join(tokens))

        return "\n".join(lines) + ("\n" if lines else "")

    def preview(self):
        text = self.build_text()
        win = tk.Toplevel(self)
        win.title("Tokenlist Preview")
        win.geometry("900x600")
        box = tk.Text(win, wrap="none")
        y = ttk.Scrollbar(win, orient="vertical", command=box.yview)
        x = ttk.Scrollbar(win, orient="horizontal", command=box.xview)
        box.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        box.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)
        box.insert("1.0", text)
        box.configure(state="disabled")

    def generate(self):
        text = self.build_text()
        if not text:
            messagebox.showwarning(APP_TITLE, "There are no configured tokens to write.")
            return
        path = filedialog.asksaveasfilename(
            title="Save tokenlist",
            initialfile="tokenlist.txt",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        Path(path).write_text(text, encoding="utf-8")
        self.status.set(f"Saved: {path}")
        messagebox.showinfo(APP_TITLE, f"Created:\n{path}")

    def clear_all(self):
        for row in self.rows:
            row["behavior"].set("Fixed")
            row["source"].set("Single word")
            row["value"].set("")
            row["length"].set("5")
            self.update_length_state(row)
        self.update_counts()

    def save_template(self):
        path = filedialog.asksaveasfilename(
            title="Save GUI template", initialfile="tokenlist_template.json",
            defaultextension=".json", filetypes=[("JSON", "*.json")]
        )
        if not path:
            return
        data = {
            "wordlist": self.wordlist_path.get(),
            "rows": [{
                "behavior": r["behavior"].get(),
                "source": r["source"].get(),
                "value": r["value"].get(),
                "length": r["length"].get(),
            } for r in self.rows]
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.status.set(f"Template saved: {path}")

    def load_template(self):
        path = filedialog.askopenfilename(
            title="Load GUI template", filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.wordlist_path.set(data.get("wordlist", self.wordlist_path.get()))
            for row, saved in zip(self.rows, data.get("rows", [])):
                row["behavior"].set(saved.get("behavior", "Fixed"))
                row["source"].set(saved.get("source", "Single word"))
                row["value"].set(saved.get("value", ""))
                saved_length = str(saved.get("length", "5"))
                valid_lengths = {str(i) for i in range(3, 9)}
                row["length"].set(saved_length if saved_length in valid_lengths else "5")
                self.update_length_state(row)
            self.update_counts()
            self.status.set(f"Template loaded: {path}")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Could not load template:\n{e}")

if __name__ == "__main__":
    TokenlistGUI().mainloop()
