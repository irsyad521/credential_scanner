import json
import os

RESULT_DIR = "result"

def ensure_result_directory():
    if not os.path.exists(RESULT_DIR):
        os.makedirs(RESULT_DIR)

def save_results_to_json(results, filename="result.json"):

    ensure_result_directory()
    filepath = os.path.join(RESULT_DIR, filename)

    if results:  
        with open(filepath, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Hasil pencarian disimpan di {filepath}")
    else:
        print(f"[-] Tidak ada hasil, file {filename} tidak dibuat.")

def save_unique_to_txt(results, category, filename):
 
    ensure_result_directory()
    unique_values = {entry[category] for entry in results if category in entry}
    filepath = os.path.join(RESULT_DIR, filename)

    if unique_values: 
        with open(filepath, "w") as f:
            for value in sorted(unique_values):
                f.write(value + "\n")
        print(f"[+] {category.capitalize()} unik disimpan di {filepath}")
    else:
        if os.path.exists(filepath):  
            os.remove(filepath)  
        print(f"[-] Tidak ada data untuk {category}, file {filename} dihapus.")
