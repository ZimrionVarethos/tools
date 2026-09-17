// Symbol-free LiME/raw triage. Linux/WSL, C++17, no third-party libraries.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using View = std::string_view;
struct Range { uint64_t offset, start, size; };
struct Mapping {
    int fd = -1; size_t size = 0; const char* data = nullptr;
    explicit Mapping(const std::string& path) {
        fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("Cannot open input: " + std::string(strerror(errno)));
        struct stat st{};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
            close(fd); throw std::runtime_error("Input must be a nonempty regular file");
        }
        size = st.st_size;
        void* p = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) { close(fd); throw std::runtime_error("mmap failed; use a 64-bit Linux/WSL environment"); }
        data = static_cast<const char*>(p);
        madvise(p, size, MADV_SEQUENTIAL);
    }
    ~Mapping() { if (data) munmap(const_cast<char*>(data), size); if (fd >= 0) close(fd); }
};
uint64_t number(const std::string& s) {
    if (s.empty() || s[0] == '-') throw std::runtime_error("Expected a nonnegative integer: " + s);
    size_t end; auto n = std::stoull(s, &end, 0);
    if (end != s.size()) throw std::runtime_error("Invalid integer: " + s);
    return n;
}
uint64_t integer(const char* p, unsigned width, bool big) {
    uint64_t n = 0;
    for (unsigned i=0; i<width; ++i) n |= uint64_t(static_cast<unsigned char>(p[i])) << (8 * (big ? width-1-i : i));
    return n;
}
std::vector<Range> ranges(const Mapping& m, bool& lime) {
    bool big = m.size >= 4 && !memcmp(m.data, "LiME", 4);
    lime = big || (m.size >= 4 && !memcmp(m.data, "EMiL", 4));
    if (!lime) return {{0, 0, m.size}};
    std::vector<Range> result;
    uint64_t pos=0, previous=0;
    while (pos < m.size) {
        if (m.size-pos < 32) throw std::runtime_error("Truncated LiME header");
        auto p=m.data+pos;
        auto start=integer(p+8, 8, big), end=integer(p+16, 8, big);
        if (integer(p,4,big)!=0x4c694d45 || integer(p+4,4,big)!=1 || end<start || end-start==UINT64_MAX ||
            (!result.empty() && start<=previous)) throw std::runtime_error("Invalid/overlapping LiME range");
        auto length=end-start+1;
        if (length>m.size-pos-32) throw std::runtime_error("Truncated LiME payload");
        result.push_back({pos+32,start,length}); previous=end; pos+=32+length;
    }
    return result;
}
bool printable(unsigned char c) { return c >= 32 && c <= 126; }
bool prefixchar(unsigned char c) { return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_' || c=='-'; }
struct Hit { const char* kind; size_t pos; };
Hit classify(View s, const std::string& kind) {
    if (kind=="strings") return {"strings",0};
    if (kind=="all" || kind=="flags") {
        size_t pos=0;
        while ((pos=s.find('{',pos))!=View::npos) {
            size_t begin=pos;
            while (begin>0 && pos-begin<40 && prefixchar(s[begin-1])) --begin;
            size_t end=s.find('}',pos+1);
            if (pos-begin>=2 && end!=View::npos && end-pos>2 && end-pos<=256) return {"flags",begin};
            ++pos;
        }
    }
    struct Pattern { const char* kind; const char* needle; };
    static const Pattern patterns[]={
        {"banners","Linux version "}, {"urls","http://"}, {"urls","https://"}, {"urls","ftp://"},
        {"commands","/bin/bash"}, {"commands","/bin/sh"}, {"commands","curl "}, {"commands","wget "},
        {"commands","sudo "}, {"commands","python3 "}, {"commands","nc -"}, {"commands","chmod "},
        {"commands","base64 -"}, {"commands","ssh "}, {"commands","history"},
        {"paths","/home/"}, {"paths","/root/"}, {"paths","/tmp/"}, {"paths","/var/www/"}, {"paths","/etc/"},
        {"secrets","password="}, {"secrets","password:"}, {"secrets","PASSWORD="},
        {"secrets","secret="}, {"secrets","token="}, {"secrets","PRIVATE KEY-----"}, {"secrets","flag="}
    };
    for (const auto& p:patterns) if (kind=="all" || kind==p.kind) {
        auto pos=s.find(p.needle);
        if (pos!=View::npos) return {p.kind,pos};
    }
    return {nullptr,0};
}
void help() {
    std::cout << "limefast MEMORY [options]\n"
        "  --kind all|flags|urls|commands|paths|secrets|banners|strings (default all)\n"
        "  --find TEXT       Exact case-sensitive byte search, repeatable; overrides --kind\n"
        "  --limit N         Stop after N rows (default 1000); 0 scans the whole dump\n"
        "  --context N       Bytes around a hit (default 120, maximum 4096)\n"
        "  --output PATH     Write TSV to a NEW file instead of stdout\n"
        "  --read OFFSET     Hexdump at FILE offset (decimal or 0x...); no full scan\n"
        "  --length N        Hexdump length (default 256, maximum 1048576)\n"
        "Offsets are file offsets plus physical addresses for LiME. Raw physical addresses are unknown.\n"
        "Heuristic ASCII triage only: no process attribution, kernel structures or file reconstruction.\n";
}
int main(int argc, char** argv) {
    FILE* out=stdout;
    try {
        std::string path, kind="all", output;
        std::vector<std::string> needles;
        uint64_t limit=1000, context=120, read=0, length=256;
        bool reading=false;
        for (int i=1;i<argc;++i) {
            std::string arg=argv[i];
            auto value=[&]() -> std::string { if (++i>=argc) throw std::runtime_error("Missing value for "+arg); return argv[i]; };
            if (arg=="--help" || arg=="-h") { help(); return 0; }
            else if (arg=="--kind") kind=value();
            else if (arg=="--find") { auto v=value(); if (v.empty()) throw std::runtime_error("Empty search term"); needles.push_back(v); }
            else if (arg=="--limit") limit=number(value());
            else if (arg=="--context") context=number(value());
            else if (arg=="--output" || arg=="-o") output=value();
            else if (arg=="--read") { reading=true; read=number(value()); }
            else if (arg=="--length") length=number(value());
            else if (!arg.empty() && arg[0]=='-') throw std::runtime_error("Unknown option: "+arg);
            else if (path.empty()) path=arg;
            else throw std::runtime_error("Unexpected argument: "+arg);
        }
        if (path.empty()) { help(); return 1; }
        const std::vector<std::string> kinds={"all","flags","urls","commands","paths","secrets","banners","strings"};
        if (std::find(kinds.begin(),kinds.end(),kind)==kinds.end()) throw std::runtime_error("Unknown kind: "+kind);
        if (context>4096 || length>1048576 || length==0) throw std::runtime_error("Context/length outside allowed bounds");
        auto began=std::chrono::steady_clock::now();
        Mapping m(path);
        bool lime=false; auto regions=ranges(m,lime);
        if (reading && (read>=m.size || length>m.size-read)) throw std::runtime_error("Read extends outside input");
        if (!output.empty()) {
            int fd=open(output.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
            if (fd<0) throw std::runtime_error("Cannot create output (must not exist): "+std::string(strerror(errno)));
            out=fdopen(fd,"w"); if (!out) { close(fd); throw std::runtime_error("Cannot open output stream"); }
        }
        if (reading) {
            for (uint64_t pos=read;pos<read+length;pos+=16) {
                fprintf(out,"%016llx  ",static_cast<unsigned long long>(pos));
                for (uint64_t j=0;j<16;++j) {
                    if (j<read+length-pos) fprintf(out,"%02x ",static_cast<unsigned char>(m.data[pos+j]));
                    else fputs("   ",out);
                }
                fputs(" |",out);
                for (uint64_t j=0;j<16 && j<read+length-pos;++j) fputc(printable(m.data[pos+j])?m.data[pos+j]:'.',out);
                fputs("|\n",out);
            }
        } else {
            fprintf(stderr,"Format: %s | Ranges: %zu | Size: %zu bytes\n",lime?"LiME":"raw/unknown",regions.size(),m.size);
            fputs("file_offset\tphysical_address\tkind\tcontext_file_offset\ttext\n",out);
            uint64_t hits=0, scanned=0; bool stopped=false;
            auto emit=[&](const Range& r, uint64_t pos, const char* category, size_t matchlen) {
                auto begin=pos>context?pos-context:0;
                auto end=pos+std::min<uint64_t>(r.size-pos,matchlen+context);
                fprintf(out,"0x%llx\t",static_cast<unsigned long long>(r.offset+pos));
                if (lime) fprintf(out,"0x%llx",static_cast<unsigned long long>(r.start+pos)); else fputc('-',out);
                fprintf(out,"\t%s\t0x%llx\t",category,static_cast<unsigned long long>(r.offset+begin));
                for (auto j=begin;j<end;++j) {
                    unsigned char c=m.data[r.offset+j];
                    if (c=='\\') fputs("\\\\",out);
                    else if (printable(c)) fputc(c,out);
                    else fprintf(out,"\\x%02x",c);
                }
                fputc('\n',out); ++hits;
                return limit && hits>=limit;
            };
            for (const auto& r:regions) {
                View data(m.data+r.offset,r.size);
                uint64_t traversed=0;
                if (!needles.empty()) {
                    // One optimized byte search per term; no decoding, regex or string allocation.
                    for (const auto& needle:needles) {
                        size_t pos=0;
                        while ((pos=data.find(needle,pos))!=View::npos) {
                            traversed=std::max<uint64_t>(traversed,pos+needle.size());
                            if (emit(r,pos,"find",needle.size())) { stopped=true; break; }
                            ++pos;
                        }
                        if (stopped) break;
                        traversed=r.size;
                    }
                } else {
                    uint64_t pos=0;
                    while (pos<r.size) {
                        while (pos<r.size && !printable(data[pos])) ++pos;
                        auto start=pos;
                        while (pos<r.size && printable(data[pos])) ++pos;
                        auto end=pos;
                        // Bounded windows with overlap retain long printable strings without allocations.
                        for (auto part=start;part<end && end-part>=4;part+=7680) {
                            View s=data.substr(part,std::min<uint64_t>(8192,end-part));
                            auto hit=classify(s,kind);
                            if (hit.kind && emit(r,part+hit.pos,hit.kind,std::min<size_t>(80,s.size()-hit.pos))) { stopped=true; break; }
                            if (end-part<=8192) break;
                        }
                        if (stopped) break;
                    }
                    traversed=pos;
                }
                scanned+=traversed;
                if (stopped) break;
            }
            auto seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-began).count();
            fprintf(stderr,"Rows: %llu | Coverage: %llu bytes | Elapsed: %.3f s | %s\n",
                static_cast<unsigned long long>(hits),static_cast<unsigned long long>(scanned),seconds,
                stopped?"STOPPED AT LIMIT (partial scan)":"COMPLETE");
        }
        if (fflush(out) || ferror(out)) throw std::runtime_error("Output write failed");
        if (out!=stdout) { auto stream=out; out=stdout; if (fclose(stream)) throw std::runtime_error("Output close failed"); }
        return 0;
    } catch (const std::exception& e) {
        if (out && out!=stdout) fclose(out);
        std::cerr << "Error: " << e.what() << '\n'; return 1;
    }
}
