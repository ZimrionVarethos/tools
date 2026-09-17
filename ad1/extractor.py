"""
AD1 File & Folder Extractor Module
"""
import os
from typing import Optional, List
from rich.progress import track
from .parser import AD1Parser
from .models import AD1Item


class AD1Extractor:
    """
    Extracts individual files, filtered items, or entire directory structures from AD1 container.
    """
    def __init__(self, parser: AD1Parser):
        self.parser = parser

    def extract_item(self, item: AD1Item, output_dir: str) -> str:
        """
        Extract a single AD1 item to the given destination directory, preserving relative path.
        """
        rel_path = item.full_path.lstrip("/")
        dest_path = os.path.join(output_dir, rel_path)

        if item.is_dir:
            os.makedirs(dest_path, exist_ok=True)
            return dest_path

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        file_bytes = self.parser.read_file_bytes(item)

        with open(dest_path, "wb") as f:
            f.write(file_bytes)

        return dest_path

    def extract_all(self, output_dir: str, show_progress: bool = True) -> int:
        """
        Extract all items in the AD1 image.
        """
        if not self.parser.items:
            self.parser.build_tree()

        items_to_extract = [item for item in self.parser.items if not item.is_dir]
        count = 0

        iterator = track(items_to_extract, description="[cyan]Extracting AD1 files...[/cyan]") if show_progress else items_to_extract

        for item in iterator:
            self.extract_item(item, output_dir)
            count += 1

        return count

    def extract_matching(self, pattern: str, output_dir: str) -> List[str]:
        """
        Extract items matching a filename or path pattern.
        """
        if not self.parser.items:
            self.parser.build_tree()

        matched_items = self.parser.find_items_by_pattern(pattern)
        extracted_paths = []

        for item in matched_items:
            if not item.is_dir:
                p = self.extract_item(item, output_dir)
                extracted_paths.append(p)

        return extracted_paths
