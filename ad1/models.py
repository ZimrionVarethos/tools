"""
AD1 File Format Data Models
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

AD1_LOGICAL_MARGIN = 512


@dataclass
class SegmentHeader:
    signature: bytes
    segment_index: int
    segment_number: int
    fragments_size: int
    header_size: int


@dataclass
class LogicalHeader:
    signature: str
    image_version: int
    zlib_chunk_size: int
    logical_metadata_addr: int
    first_item_addr: int
    data_source_name_length: int
    ad_signature: str
    data_source_name_addr: int
    attrguid_footer_addr: int
    locsguid_footer_addr: int
    data_source_name: str


@dataclass
class AD1Metadata:
    next_metadata_addr: int
    category: int
    key: int
    data_length: int
    raw_data: bytes
    text_data: str = ""


# AD1 Item Type Signatures
ITEM_TYPE_REGULAR_FILE = 0x31
ITEM_TYPE_PLACEHOLDER = 0x32
ITEM_TYPE_REGULAR_FOLDER = 0x33
ITEM_TYPE_FILESYSTEM_METADATA = 0x34
ITEM_TYPE_FILESLACK = 0x36
ITEM_TYPE_SYMLINK = 0x39

AD1_FOLDER_SIGNATURE = 0x05


@dataclass
class AD1Item:
    address: int
    next_item_addr: int
    first_child_addr: int
    first_metadata_addr: int
    zlib_metadata_addr: int
    decompressed_size: int
    item_type: int
    item_name_length: int
    item_name: str
    parent_folder_addr: int
    
    # Hierarchy
    parent: Optional['AD1Item'] = None
    children: List['AD1Item'] = field(default_factory=list)
    next_item: Optional['AD1Item'] = None
    
    # Metadata map: (category, key) -> AD1Metadata
    metadata: Dict[int, List[AD1Metadata]] = field(default_factory=dict)
    
    # Timestamps
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    accessed_time: Optional[str] = None
    
    # Hashes
    md5: Optional[str] = None
    sha1: Optional[str] = None

    @property
    def is_dir(self) -> bool:
        return self.item_type == AD1_FOLDER_SIGNATURE or self.first_child_addr != 0 or bool(self.children)

    @property
    def full_path(self) -> str:
        """
        Compute full path from root of AD1 image.
        """
        parts = []
        curr: Optional['AD1Item'] = self
        while curr is not None:
            if curr.item_name:
                parts.append(curr.item_name)
            curr = curr.parent
        return "/".join(reversed(parts)) if parts else self.item_name
