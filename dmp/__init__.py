"""
Windows Memory Dump (DMP) Forensics Engine Module
"""
from dmp.dmp_engine import DMPEngine, DMPModule, DMPMemorySegment
from dmp.scanner import DMPScanner, main as dmpscan_main
from dmp.dumper import main as dmpdump_main
