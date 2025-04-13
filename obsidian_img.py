import os
import re
from urllib.parse import quote

# Base paths
markdown_root = "/home/soren/Documents/webappsec"
image_base_url = "https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/"
image_local_path = os.path.join(markdown_root, "_img")

# Regex pattern for [[ Pasted image {number}.png | {width} ]]
pattern = re.compile(r"!\[\[\s*Pasted image (\d+)\.png\s*\|\s*(\d+)\s*\]\]")

# Walk through all markdown files
for root, dirs, files in os.walk(markdown_root):
    for file in files:
        if file.endswith(".md"):
            md_path = os.path.join(root, file)

            with open(md_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Replace all image references
            def replace_match(match):
                number, width = match.groups()
                filename = f"Pasted image {number}.png"
                quoted_filename = quote(filename)
                return f'<img src="{image_base_url}{quoted_filename}" width="{width}"/>'

            new_content = pattern.sub(replace_match, content)

            # Overwrite the markdown file
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(new_content)

print("All markdown files have been processed.")
