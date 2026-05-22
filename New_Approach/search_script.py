import os

def main():
    keywords = ["cfm", "cicflowmeter"]
    workspace = "C:\\CogSOC"
    output_lines = []
    for root, dirs, files in os.walk(workspace):
        if "cogsoc_env" in root or "cic_env" in root or ".git" in root:
            continue
        for file in files:
            if file.endswith(".py") and file != "search_script.py":
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, 1):
                            if any(kw in line.lower() for kw in keywords):
                                output_lines.append(f"{filepath}:{line_no}: {line.strip()}\n")
                except Exception as e:
                    output_lines.append(f"Error reading {filepath}: {e}\n")
    
    with open("search_results.txt", "w", encoding="utf-8") as out:
        out.writelines(output_lines)
    print("Done. Results in search_results.txt")

if __name__ == "__main__":
    main()

