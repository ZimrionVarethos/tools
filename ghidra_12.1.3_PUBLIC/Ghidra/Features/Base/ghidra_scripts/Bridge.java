// Ghidra On-Demand AI Companion Bridge Server (Bridge.java)
// @author Antigravity DFIR Assistant
// @category Assembly Companion
// @keybinding
// @menupath Tools.AI Companion Bridge
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.HashSet;
import java.util.Set;
import java.nio.charset.StandardCharsets;

public class Bridge extends GhidraScript {

    private static HttpServer activeServer = null;
    private static Bridge currentScriptInstance = null;
    private static Program boundProgram = null;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("[-] No active program loaded in Ghidra. Open a binary first!");
            return;
        }

        currentScriptInstance = this;
        boundProgram = currentProgram;

        // Toggle Server: If already running, stop it
        if (activeServer != null) {
            try {
                activeServer.stop(0);
                activeServer = null;
                println("\n=================================================");
                println("   🛑 Ghidra Bridge Server STOPPED.");
                println("=================================================");
            } catch (Exception e) {
                activeServer = null;
            }
            return;
        }

        // Dynamic Port Finder: Try binding ports 13370..13375 without error
        int boundPort = -1;
        for (int p = 13370; p <= 13375; p++) {
            try {
                activeServer = HttpServer.create(new InetSocketAddress("0.0.0.0", p), 0);
                boundPort = p;
                break;
            } catch (java.net.BindException be) {
                // Port busy, try next
            }
        }

        if (activeServer == null) {
            printerr("[-] Could not bind to any port between 13370 and 13375.");
            return;
        }

        // Save active port to user home file
        try {
            java.io.File portFile = new java.io.File(System.getProperty("user.home"), ".ghidra_bridge_port");
            java.nio.file.Files.write(portFile.toPath(), String.valueOf(boundPort).getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {}

        // Core Endpoints
        activeServer.createContext("/status", new StatusHandler());
        activeServer.createContext("/current", new CurrentHandler());
        activeServer.createContext("/decompile", new DecompileHandler());
        activeServer.createContext("/rename", new RenameHandler());
        activeServer.createContext("/comment", new CommentHandler());
        activeServer.createContext("/xrefs", new XrefsHandler());
        activeServer.createContext("/strings", new StringsHandler());

        // Advanced Navigation & Analysis Endpoints
        activeServer.createContext("/goto", new GotoHandler());
        activeServer.createContext("/search", new SearchHandler());
        activeServer.createContext("/callers", new CallersHandler());
        activeServer.createContext("/callees", new CalleesHandler());
        activeServer.createContext("/vars", new VarsHandler());

        // Shutdown Endpoint
        activeServer.createContext("/stop", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                sendJson(exchange, 200, "{\"status\":\"stopped\",\"message\":\"Ghidra Bridge Server stopped successfully\"}");
                new Thread(() -> {
                    try { Thread.sleep(100); } catch (Exception e) {}
                    if (activeServer != null) {
                        activeServer.stop(0);
                        activeServer = null;
                    }
                }).start();
            }
        });

        activeServer.setExecutor(Executors.newFixedThreadPool(4));
        activeServer.start();

        println("=================================================");
        println("   🤖 Ghidra Full-Featured Bridge (Bridge.java) ");
        println("=================================================");
        println("[+] Target Program: " + currentProgram.getName());
        println("[+] Listening on: http://127.0.0.1:" + boundPort + " (All Interfaces)");
        println("[+] Features: Live Cursor Tracking, Goto, Search, Call Tree, Vars, Decompile");
        println("[+] Cara Stop: Jalankan 'ghidraanalyze stop' di terminal atau klik Run Bridge.java lagi");
        println("=================================================\n");
    }

    private void sendJson(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private Address parseAddress(Program prog, String addrStr) {
        if (prog == null || addrStr == null) return null;
        if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
            addrStr = addrStr.substring(2);
        }
        return prog.getAddressFactory().getAddress(addrStr);
    }

    // --- Handlers ---

    class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            if (prog == null) {
                sendJson(exchange, 200, "{\"status\":\"running\",\"program\":\"None\",\"base\":\"0x0\"}");
                return;
            }
            String json = "{\"status\":\"running\",\"program\":\"" + escapeJson(prog.getName()) +
                          "\",\"base\":\"0x" + Long.toHexString(prog.getImageBase().getOffset()) +
                          "\",\"min_addr\":\"0x" + prog.getMinAddress() + "\",\"max_addr\":\"0x" + prog.getMaxAddress() + "\"}";
            sendJson(exchange, 200, json);
        }
    }

    class GotoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String addrStr = null;
            if (query != null && query.contains("addr=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("addr=")) {
                        addrStr = param.substring(5);
                    }
                }
            }

            if (addrStr == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing addr parameter\"}");
                return;
            }

            try {
                Address targetAddr = parseAddress(prog, addrStr);
                if (targetAddr != null && currentScriptInstance != null) {
                    SwingUtilities.invokeLater(() -> {
                        currentScriptInstance.goTo(targetAddr);
                    });
                    sendJson(exchange, 200, "{\"status\":\"success\",\"message\":\"Navigated Ghidra GUI to 0x" + targetAddr + "\"}");
                } else {
                    sendJson(exchange, 404, "{\"error\":\"Invalid address: " + addrStr + "\"}");
                }
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class CurrentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            Address curAddr = null;

            // Try to get real-time dynamic cursor location from active Ghidra Tool
            try {
                if (currentScriptInstance != null && currentScriptInstance.getState() != null) {
                    PluginTool tool = currentScriptInstance.getState().getTool();
                    if (tool != null) {
                        CodeViewerService cvs = tool.getService(CodeViewerService.class);
                        if (cvs != null && cvs.getCurrentLocation() != null) {
                            curAddr = cvs.getCurrentLocation().getAddress();
                            if (cvs.getCurrentLocation().getProgram() != null) {
                                prog = cvs.getCurrentLocation().getProgram();
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Fallback
            }

            if (curAddr == null) {
                curAddr = currentLocation != null ? currentLocation.getAddress() : (prog != null ? prog.getMinAddress() : null);
            }

            if (curAddr == null || prog == null) {
                sendJson(exchange, 200, "{\"error\":\"No address found or no program loaded\"}");
                return;
            }

            Function func = prog.getFunctionManager().getFunctionContaining(curAddr);
            String funcName = func != null ? func.getName() : "None";
            String entryAddr = func != null ? func.getEntryPoint().toString() : curAddr.toString();

            String decompCode = "";
            if (func != null) {
                DecompInterface decomp = new DecompInterface();
                decomp.openProgram(prog);
                DecompileResults res = decomp.decompileFunction(func, 30, null);
                if (res.decompileCompleted()) {
                    decompCode = res.getDecompiledFunction().getC();
                }
                decomp.dispose();
            }

            String json = "{\"address\":\"0x" + curAddr.toString() + "\",\"function\":\"" + escapeJson(funcName) +
                          "\",\"entry\":\"0x" + entryAddr + "\",\"code\":\"" + escapeJson(decompCode) + "\"}";
            sendJson(exchange, 200, json);
        }
    }

    class DecompileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String addrStr = null;
            if (query != null && query.contains("addr=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("addr=")) {
                        addrStr = param.substring(5);
                    }
                }
            }

            if (addrStr == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing addr query parameter or no program loaded\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                Function func = prog.getFunctionManager().getFunctionContaining(addr);
                if (func == null) {
                    sendJson(exchange, 404, "{\"error\":\"No function found at address: 0x" + addrStr + "\"}");
                    return;
                }

                DecompInterface decomp = new DecompInterface();
                decomp.openProgram(prog);
                DecompileResults res = decomp.decompileFunction(func, 30, null);
                String cCode = res.decompileCompleted() ? res.getDecompiledFunction().getC() : "/* Decompilation Failed */";
                decomp.dispose();

                String json = "{\"function\":\"" + escapeJson(func.getName()) + "\",\"entry\":\"0x" + func.getEntryPoint().toString() +
                              "\",\"code\":\"" + escapeJson(cCode) + "\"}";
                sendJson(exchange, 200, json);
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class SearchHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String term = "";
            String type = "all";

            if (query != null) {
                for (String param : query.split("&")) {
                    if (param.startsWith("q=")) term = param.substring(2);
                    if (param.startsWith("type=")) type = param.substring(5);
                }
            }

            if (term.isEmpty() || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing search query 'q'\"}");
                return;
            }

            term = java.net.URLDecoder.decode(term, StandardCharsets.UTF_8).toLowerCase();
            StringBuilder sb = new StringBuilder("{\"query\":\"" + escapeJson(term) + "\",\"results\":[");
            int count = 0;

            if (type.equals("all") || type.equals("string")) {
                Listing listing = prog.getListing();
                for (Data data : listing.getDefinedData(true)) {
                    if (count >= 50) break;
                    if (data.hasStringValue()) {
                        String sVal = data.getValue() != null ? data.getValue().toString() : "";
                        if (sVal.toLowerCase().contains(term)) {
                            if (count > 0) sb.append(",");
                            sb.append("{\"type\":\"string\",\"addr\":\"0x").append(data.getAddress().toString())
                              .append("\",\"name\":\"").append(escapeJson(sVal)).append("\"}");
                            count++;
                        }
                    }
                }
            }

            if ((type.equals("all") || type.equals("symbol") || type.equals("api")) && count < 50) {
                SymbolTable symTab = prog.getSymbolTable();
                SymbolIterator symIter = symTab.getAllSymbols(true);
                while (symIter.hasNext() && count < 50) {
                    Symbol sym = symIter.next();
                    String name = sym.getName();
                    if (name.toLowerCase().contains(term)) {
                        if (count > 0) sb.append(",");
                        String cat = sym.isExternal() ? "api_import" : (sym.getSymbolType().toString().toLowerCase());
                        sb.append("{\"type\":\"").append(cat).append("\",\"addr\":\"0x").append(sym.getAddress().toString())
                          .append("\",\"name\":\"").append(escapeJson(name)).append("\"}");
                        count++;
                    }
                }
            }

            sb.append("]}");
            sendJson(exchange, 200, sb.toString());
        }
    }

    class CallersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String addrStr = null;
            if (query != null && query.contains("addr=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("addr=")) addrStr = param.substring(5);
                }
            }

            if (addrStr == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing addr parameter\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                Function func = prog.getFunctionManager().getFunctionContaining(addr);
                Address targetAddr = (func != null) ? func.getEntryPoint() : addr;

                Set<Function> callingFunctions = (func != null) ? func.getCallingFunctions(null) : new HashSet<>();
                StringBuilder sb = new StringBuilder("{\"target\":\"0x" + targetAddr + "\",\"callers\":[");

                int idx = 0;
                for (Function caller : callingFunctions) {
                    if (idx > 0) sb.append(",");
                    sb.append("{\"name\":\"").append(escapeJson(caller.getName()))
                      .append("\",\"entry\":\"0x").append(caller.getEntryPoint().toString()).append("\"}");
                    idx++;
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class CalleesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String addrStr = null;
            if (query != null && query.contains("addr=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("addr=")) addrStr = param.substring(5);
                }
            }

            if (addrStr == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing addr parameter\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                Function func = prog.getFunctionManager().getFunctionContaining(addr);
                if (func == null) {
                    sendJson(exchange, 404, "{\"error\":\"No function found at " + addrStr + "\"}");
                    return;
                }

                Set<Function> calledFunctions = func.getCalledFunctions(null);
                StringBuilder sb = new StringBuilder("{\"function\":\"" + escapeJson(func.getName()) + "\",\"callees\":[");

                int idx = 0;
                for (Function callee : calledFunctions) {
                    if (idx > 0) sb.append(",");
                    sb.append("{\"name\":\"").append(escapeJson(callee.getName()))
                      .append("\",\"entry\":\"0x").append(callee.getEntryPoint().toString())
                      .append("\",\"is_external\":").append(callee.isExternal()).append("}");
                    idx++;
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class VarsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String addrStr = null;
            if (query != null && query.contains("addr=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("addr=")) addrStr = param.substring(5);
                }
            }

            if (addrStr == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing addr parameter\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                Function func = prog.getFunctionManager().getFunctionContaining(addr);
                if (func == null) {
                    sendJson(exchange, 404, "{\"error\":\"No function at address " + addrStr + "\"}");
                    return;
                }

                StringBuilder sb = new StringBuilder("{\"function\":\"" + escapeJson(func.getName()) + "\",\"variables\":[");
                Variable[] vars = func.getAllVariables();

                for (int i = 0; i < vars.length; i++) {
                    if (i > 0) sb.append(",");
                    Variable v = vars[i];
                    String kind = (v instanceof Parameter) ? "parameter" : "local_var";
                    sb.append("{\"name\":\"").append(escapeJson(v.getName()))
                      .append("\",\"type\":\"").append(escapeJson(v.getDataType().getName()))
                      .append("\",\"kind\":\"").append(kind)
                      .append("\",\"size\":").append(v.getLength())
                      .append(",\"storage\":\"").append(escapeJson(v.getVariableStorage().toString())).append("\"}");
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class RenameHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            InputStream is = exchange.getRequestBody();
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            String addrStr = extractJsonField(body, "addr");
            String newName = extractJsonField(body, "name");

            if (addrStr == null || newName == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing 'addr' or 'name' in JSON body\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                Function func = prog.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = prog.getFunctionManager().getFunctionContaining(addr);
                }

                if (func != null) {
                    int txId = prog.startTransaction("Rename Function via AI Companion");
                    func.setName(newName, SourceType.USER_DEFINED);
                    prog.endTransaction(txId, true);
                    sendJson(exchange, 200, "{\"status\":\"success\",\"message\":\"Renamed function to " + escapeJson(newName) + "\"}");
                } else {
                    sendJson(exchange, 404, "{\"error\":\"Function not found at " + addrStr + "\"}");
                }
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class CommentHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            InputStream is = exchange.getRequestBody();
            String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            String addrStr = extractJsonField(body, "addr");
            String comment = extractJsonField(body, "comment");

            if (addrStr == null || comment == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing 'addr' or 'comment' in JSON body\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                Listing listing = prog.getListing();
                CodeUnit cu = listing.getCodeUnitAt(addr);

                if (cu != null) {
                    int txId = prog.startTransaction("Add Comment via AI Companion");
                    cu.setComment(0, comment);
                    prog.endTransaction(txId, true);
                    sendJson(exchange, 200, "{\"status\":\"success\",\"message\":\"Comment added successfully\"}");
                } else {
                    sendJson(exchange, 404, "{\"error\":\"No code unit found at " + addrStr + "\"}");
                }
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class XrefsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            String query = exchange.getRequestURI().getQuery();
            String addrStr = null;
            if (query != null && query.contains("addr=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("addr=")) addrStr = param.substring(5);
                }
            }

            if (addrStr == null || prog == null) {
                sendJson(exchange, 400, "{\"error\":\"Missing addr parameter\"}");
                return;
            }

            try {
                Address addr = parseAddress(prog, addrStr);
                ReferenceManager refMgr = prog.getReferenceManager();
                ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                StringBuilder sb = new StringBuilder("{\"address\":\"0x" + addrStr + "\",\"xrefs\":[");
                boolean first = true;
                while (refIter != null && refIter.hasNext()) {
                    Reference ref = refIter.next();
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("{\"from\":\"0x").append(ref.getFromAddress().toString())
                      .append("\",\"type\":\"").append(ref.getReferenceType().toString()).append("\"}");
                }
                sb.append("]}");
                sendJson(exchange, 200, sb.toString());
            } catch (Exception e) {
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
            }
        }
    }

    class StringsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Program prog = boundProgram != null ? boundProgram : currentProgram;
            if (prog == null) {
                sendJson(exchange, 200, "{\"strings\":[]}");
                return;
            }
            Listing listing = prog.getListing();
            StringBuilder sb = new StringBuilder("{\"strings\":[");
            int count = 0;

            for (Data data : listing.getDefinedData(true)) {
                if (count > 200) break;
                if (data.hasStringValue()) {
                    if (count > 0) sb.append(",");
                    String sVal = data.getValue() != null ? data.getValue().toString() : "";
                    sb.append("{\"addr\":\"0x").append(data.getAddress().toString())
                      .append("\",\"value\":\"").append(escapeJson(sVal)).append("\"}");
                    count++;
                }
            }
            sb.append("]}");
            sendJson(exchange, 200, sb.toString());
        }
    }

    private String extractJsonField(String json, String field) {
        String key = "\"" + field + "\":";
        int idx = json.indexOf(key);
        if (idx == -1) return null;
        int start = json.indexOf("\"", idx + key.length());
        if (start == -1) return null;
        int end = json.indexOf("\"", start + 1);
        if (end == -1) return null;
        return json.substring(start + 1, end);
    }
}
