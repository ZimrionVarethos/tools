#!/usr/bin/env python3
"""
Audio Steganography & Spectrogram Visualizer (stegoaudio)
Generates high-resolution FFT Spectrograms and extracts LSB audio bitstreams to uncover hidden flags in sound frequencies.
"""

import sys
import os
import argparse
import wave
import numpy as np

# Add project root to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rich.console import Console
from rich.panel import Panel

from core.banner import print_banner
from core.utils import is_ascii_printable

console = Console(force_terminal=True, legacy_windows=False)

def generate_spectrogram(audio_path: str, out_png: str, n_fft: int = 1024, cmap: str = "inferno") -> bool:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from scipy.io import wavfile
        from scipy import signal

        # If mp3 or other format, convert to temp wav via ffmpeg/sox if needed
        temp_wav = None
        target_wav = audio_path
        if not audio_path.lower().endswith(".wav"):
            import subprocess
            temp_wav = out_png.replace(".png", "_temp.wav")
            subprocess.run(["ffmpeg", "-y", "-i", audio_path, temp_wav], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            target_wav = temp_wav

        sample_rate, samples = wavfile.read(target_wav)

        # If stereo, take first channel
        if samples.ndim > 1:
            samples = samples[:, 0]

        # Calculate spectrogram
        frequencies, times, spectrogram = signal.spectrogram(samples, sample_rate, nperseg=n_fft)

        # Plot high-res spectrogram
        plt.figure(figsize=(14, 6), dpi=200)
        plt.pcolormesh(times, frequencies, 10 * np.log10(spectrogram + 1e-10), shading='gouraud', cmap=cmap)
        plt.ylabel('Frequency [Hz]', fontsize=12)
        plt.xlabel('Time [sec]', fontsize=12)
        plt.title(f'Audio Spectrogram: {os.path.basename(audio_path)}', fontsize=14, fontweight='bold')
        plt.colorbar(label='Intensity [dB]')
        plt.tight_layout()
        plt.savefig(out_png)
        plt.close()

        if temp_wav and os.path.exists(temp_wav):
            os.remove(temp_wav)

        return True
    except Exception as e:
        console.print(f"[bold red]Error generating spectrogram:[/bold red] {e}")
        return False

def extract_wav_lsb(wav_path: str, out_bin: str) -> bool:
    try:
        with wave.open(wav_path, 'rb') as w:
            n_frames = w.getnframes()
            frames = w.readframes(n_frames)
            sampwidth = w.getsampwidth()

        # Extract 1 LSB per sample
        bits = []
        for i in range(0, len(frames), sampwidth):
            sample_byte = frames[i]
            bits.append(sample_byte & 1)

        # Pack bits
        pad = (8 - (len(bits) % 8)) % 8
        padded_bits = bits + [0] * pad
        raw_bytes = np.packbits(padded_bits).tobytes()

        with open(out_bin, "wb") as f:
            f.write(raw_bytes)

        return True
    except Exception as e:
        return False

def main(args=None):
    parser = argparse.ArgumentParser(
        prog="stegoaudio",
        description=" Audio Steganography & Spectrogram Visualizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  stegoaudio recording.wav
  stegoaudio sound.mp3 -o ./spectrogram.png --cmap magma
  stegoaudio voice.wav --lsb
        """
    )
    parser.add_argument("file", help="Target audio file (.wav, .mp3, .ogg, .flac)")
    parser.add_argument("-o", "--output", help="Destination PNG path for spectrogram (default: ./<filename>_spectrogram.png)")
    parser.add_argument("--lsb", action="store_true", help="Extract raw LSB bitstream from WAV samples")
    parser.add_argument("--fft", type=int, default=1024, help="FFT window size for spectrogram resolution (default: 1024)")
    parser.add_argument("--cmap", default="inferno", help="Matplotlib color map (inferno, magma, viridis, plasma, bone)")

    args = parser.parse_args(args)

    if not os.path.exists(args.file):
        console.print(f"[bold red]Error: File not found: {args.file}[/bold red]")
        sys.exit(1)

    print_banner(tool_name="AUDIO STEGANOGRAPHY ANALYZER (stegoaudio)", sub_title="FFT Frequency Spectrogram & LSB Extraction")

    file_path = os.path.abspath(args.file)
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    out_png = os.path.abspath(args.output) if args.output else os.path.abspath(f"./{base_name}_spectrogram.png")

    console.print(f"[bold cyan]Audio Target:[/bold cyan] [bold white]{os.path.basename(file_path)}[/bold white]")
    console.print(f"[bold cyan]Spectrogram Destination:[/bold cyan] [bold magenta]{out_png}[/bold magenta]\n")

    console.print(f"[bold cyan]Generating high-resolution FFT Spectrogram (Window: {args.fft}, Cmap: {args.cmap})...[/bold cyan]")
    if generate_spectrogram(file_path, out_png, n_fft=args.fft, cmap=args.cmap):
        console.print(f"[bold green] Spectrogram successfully generated and saved to {out_png}![/bold green]")
        console.print("[dim]Buka gambar spectrogram untuk melihat teks/gambar/morse yang digambar pada frekuensi suara.[/dim]\n")

    if args.lsb:
        out_lsb = os.path.abspath(f"./{base_name}_lsb.bin")
        console.print(f"[bold cyan]Extracting WAV LSB bitstream to {out_lsb}...[/bold cyan]")
        if extract_wav_lsb(file_path, out_lsb):
            console.print(f"[bold green] LSB data saved ({os.path.getsize(out_lsb)} bytes)[/bold green]\n")

if __name__ == "__main__":
    main()
