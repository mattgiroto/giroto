import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

cmdb_path = None
second_path = None


def load_csv(path):
    df = pd.read_csv(path, header=None)
    df = df.iloc[:, :2]
    df.columns = ["SERVER", "SOFTWARE"]
    df["SERVER"] = df["SERVER"].astype(str).str.strip().str.upper()
    df["SOFTWARE"] = df["SOFTWARE"].astype(str).str.strip().str.upper()
    return set(zip(df["SERVER"], df["SOFTWARE"]))


def select_cmdb():
    global cmdb_path
    cmdb_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    cmdb_label.config(text=cmdb_path.split("/")[-1])


def select_second():
    global second_path
    second_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    second_label.config(text=second_path.split("/")[-1])


def compare():
    if not cmdb_path or not second_path:
        messagebox.showerror("Error", "Please, select both CSV.")
        return

    cmdb_set = load_csv(cmdb_path)
    second_set = load_csv(second_path)

    results = []

    all_items = cmdb_set.union(second_set)

    for server, software in all_items:
        in_cmdb = (server, software) in cmdb_set
        in_second = (server, software) in second_set

        status = "OK" if in_cmdb and in_second else "NOK"

        results.append({
            "SERVERNAME": server,
            "SOFTWARE": software,
            "CMDB": "YES" if in_cmdb else "NO",
            "2ND_SOURCE": "YES" if in_second else "NO",
            "STATUS": status
        })

    result_df = pd.DataFrame(results)

    # Save CSV
    output_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save results"
    )

    if output_path:
        result_df.to_csv(output_path, index=False)

    # Display results
    text_area.delete("1.0", tk.END)
    nok = result_df[result_df["STATUS"] == "NOK"]

    if nok.empty:
        text_area.insert(tk.END, "✅ NO desviations found.\n")
    else:
        text_area.insert(tk.END, f"❌ Deviation found: {len(nok)}\n\n")
        text_area.insert(tk.END, nok.to_string(index=False))


# GUI
root = tk.Tk()
root.title("QIV - Compare Tool")
root.geometry("850x550")

tk.Button(root, text="Attach CMDB Baseline", command=select_cmdb).pack(pady=5)
cmdb_label = tk.Label(root, text="None attached")
cmdb_label.pack()

tk.Button(root, text="Attach 2ND Source Baseline", command=select_second).pack(pady=5)
second_label = tk.Label(root, text="None attached")
second_label.pack()

tk.Button(root, text="START", command=compare, bg="#222", fg="white").pack(pady=15)

text_area = scrolledtext.ScrolledText(root, width=100, height=20)
text_area.pack(padx=10, pady=10)

root.mainloop()
