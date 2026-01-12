import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;                                                                   import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Japache {

    private static volatile boolean running = true;
    private static ServerSocket serverSocket;
    private static ExecutorService threadPool;
    private static final Configuration config = new Configuration();
    private static final AccessManager accessManager = new AccessManager();
    private static final Logger logger = new Logger();

    public static void main(String[] args) {
        try {
            config.load();
            accessManager.load();
            logger.init();

            System.out.println("[info]: Japache demarre sur le port " + config.getPort());

            threadPool = Executors.newFixedThreadPool(config.getMaxThreads());
            serverSocket = new ServerSocket(config.getPort());

            Thread serverThread = new Thread(() -> {
                while (running) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        threadPool.execute(new ConnectionHandler(clientSocket));
                    } catch (IOException e) {
                        if (running) {
                            e.printStackTrace();
                        }
                    }
                }
            });
            serverThread.start();

            Scanner console = new Scanner(System.in);
            while (running) {
                if (console.hasNextLine()) {
                    String line = console.nextLine();
                    if ("stop".equalsIgnoreCase(line.trim())) {
                        running = false;
                        shutdown();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void shutdown() {
        System.out.println("Arret du serveur...");
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            if (threadPool != null) {
                threadPool.shutdownNow();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.exit(0);
    }

    static class Configuration {
        private int port = 80;
        private int maxThreads = 50;
        private String webRoot = "webroot";
        private String errorDir = "error";
        private String logDir = "log";
        private String configDir = "config";
        private String indexFile = "index.html";
        private boolean showDirectoryListing = false;

        public void load() throws IOException {
            File file = new File(configDir + "/config.conf");
            if (!file.exists()) {
                createDefaultConfig(file);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        String key = parts[0].trim();
                        String val = parts[1].trim();
                        switch (key.toLowerCase()) {
                            case "port": port = Integer.parseInt(val); break;
                            case "max_threads": maxThreads = Integer.parseInt(val); break;
                            case "webroot": webRoot = val; break;
                            case "error_dir": errorDir = val; break;
                            case "log_dir": logDir = val; break;
                            case "index_file": indexFile = val; break;
                            case "directory_listing": showDirectoryListing = Boolean.parseBoolean(val); break;
                        }
                    }
                }
            }
        }

        private void createDefaultConfig(File f) throws IOException {
            f.getParentFile().mkdirs();
            try (PrintWriter pw = new PrintWriter(f)) {
                pw.println("PORT=8080");
                pw.println("MAX_THREADS=100");
                pw.println("WEBROOT=webroot");
                pw.println("ERROR_DIR=error");
                pw.println("LOG_DIR=log");
                pw.println("INDEX_FILE=index.html");
                pw.println("DIRECTORY_LISTING=true");
            }
        }

        public int getPort() { return port; }
        public int getMaxThreads() { return maxThreads; }
        public String getWebRoot() { return webRoot; }
        public String getErrorDir() { return errorDir; }
        public String getLogDir() { return logDir; }
        public String getConfigDir() { return configDir; }
        public String getIndexFile() { return indexFile; }
        public boolean isShowDirectoryListing() { return showDirectoryListing; }
    }

    static class AccessManager {
        private final List<AccessRule> rules = new ArrayList<>();

        public void load() throws IOException {
            File file = new File(config.getConfigDir() + "/access.conf");
            if (!file.exists()) {
                createDefaultAccess(file);
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)))) {
                String line;
                String currentPath = null;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    if (line.startsWith("<Directory")) {
                        int start = line.indexOf("\"");
                        int end = line.lastIndexOf("\"");
                        if (start != -1 && end != -1) {
                            currentPath = line.substring(start + 1, end);
                        }
                    } else if (line.startsWith("</Directory>")) {
                        currentPath = null;
                    } else if (line.startsWith("Order")) {

                    } else if (line.toUpperCase().startsWith("DENY FROM")) {
                        String ip = line.substring(9).trim();
                        if (currentPath != null) {
                            rules.add(new AccessRule(currentPath, ip, false));
                        }
                    } else if (line.toUpperCase().startsWith("ALLOW FROM")) {
                        String ip = line.substring(10).trim();
                        if (currentPath != null) {
                            rules.add(new AccessRule(currentPath, ip, true));
                        }
                    }
                }
            }
        }

        private void createDefaultAccess(File f) throws IOException {
            try (PrintWriter pw = new PrintWriter(f)) {
                pw.println("<Directory \"/\">");
                pw.println("Allow from all");
                pw.println("</Directory>");
            }
        }

        public boolean isAllowed(String path, String ip) {
            boolean allowed = true;
            for (AccessRule rule : rules) {
                if (path.startsWith(rule.path)) {
                    if (rule.targetIp.equalsIgnoreCase("all")) {
                        allowed = rule.allow;
                    } else if (rule.targetIp.equals(ip)) {
                        allowed = rule.allow;
                    }
                }
            }
            return allowed;
        }
    }

    static class AccessRule {
        String path;
        String targetIp;
        boolean allow;

        public AccessRule(String path, String targetIp, boolean allow) {
            this.path = path;
            this.targetIp = targetIp;
            this.allow = allow;
        }
    }

    static class Logger {
        private PrintWriter accessLog;
        private PrintWriter errorLog;
        private final Object lock = new Object();

        public void init() throws IOException {
            File dir = new File(config.getLogDir());
            if (!dir.exists()) dir.mkdirs();
            accessLog = new PrintWriter(new FileOutputStream(new File(dir, "access.log"), true), true);
            errorLog = new PrintWriter(new FileOutputStream(new File(dir, "error.log"), true), true);
        }

        public void logAccess(String ip, String request, int status, long size) {
            synchronized (lock) {
                String time = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH)
                        .format(LocalDateTime.now().atZone(ZoneId.systemDefault()));
                accessLog.printf("%s - - [%s] \"%s\" %d %d%n", ip, time, request, status, size);
            }
        }

        public void logError(String message, Throwable t) {
            synchronized (lock) {
                String time = DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(LocalDateTime.now());
                errorLog.printf("[%s] [error] %s%n", time, message);
                if (t != null) t.printStackTrace(errorLog);
            }
        }
    }

    static class ConnectionHandler implements Runnable {
        private final Socket socket;

        public ConnectionHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                InputStream in = socket.getInputStream();
                OutputStream out = new BufferedOutputStream(socket.getOutputStream());

                HttpRequest request = HttpRequest.parse(in);
                HttpResponse response = new HttpResponse();

                if (request == null) {
                    socket.close();
                    return;
                }

                String path = request.getPath();
                String ip = socket.getInetAddress().getHostAddress();

                if (!accessManager.isAllowed(path, ip)) {
                    sendError(response, 403, "Forbidden");
                } else {
                    handleRequest(request, response);
                }

                response.write(out);
                out.flush();

                logger.logAccess(ip, request.getMethod() + " " + request.getUri() + " " + request.getVersion(),
                        response.getStatus(), response.getContentLength());

            } catch (Exception e) {
                logger.logError("Erreur traitement connection", e);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {

                }
            }
        }

        private void handleRequest(HttpRequest req, HttpResponse res) {
            if (!req.getMethod().equals("GET") && !req.getMethod().equals("HEAD") && !req.getMethod().equals("POST")) {
                sendError(res, 501, "Not Implemented");
                return;
            }

            String cleanPath = req.getPath().replace("..", "");
            File file = new File(config.getWebRoot(), cleanPath);

            if (!file.exists()) {
                sendError(res, 404, "Not Found");
                return;
            }

            if (file.isDirectory()) {
                File index = new File(file, config.getIndexFile());
                if (index.exists()) {
                    file = index;
                } else if (config.isShowDirectoryListing()) {
                    sendDirectoryListing(res, file, req.getPath());
                    return;
                } else {
                    sendError(res, 403, "Forbidden");
                    return;
                }
            }

            try {
                byte[] content = Files.readAllBytes(file.toPath());
                res.setStatus(200);
                res.setHeader("Content-Type", MimeTypes.get(file.getName()));
                res.setHeader("Content-Length", String.valueOf(content.length));
                res.setBody(content);
            } catch (IOException e) {
                sendError(res, 500, "Internal Server Error");
            }
        }

        private void sendDirectoryListing(HttpResponse res, File dir, String path) {
            StringBuilder html = new StringBuilder();
            html.append("<html><head><title>Index of ").append(path).append("</title></head>");
            html.append("<body><h1>Index of ").append(path).append("</h1><hr><pre>");

            if (!path.equals("/")) {
                html.append("<a href=\"../\">../</a>\n");
            }

            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    String name = f.getName();
                    if (f.isDirectory()) name += "/";
                    html.append("<a href=\"").append(name).append("\">").append(name).append("</a>\n");
                }
            }
            html.append("</pre><hr></body></html>");

            byte[] bytes = html.toString().getBytes(StandardCharsets.UTF_8);
            res.setStatus(200);
            res.setHeader("Content-Type", "text/html");
            res.setHeader("Content-Length", String.valueOf(bytes.length));
            res.setBody(bytes);
        }

        private void sendError(HttpResponse res, int code, String text) {
            res.setStatus(code);
            File errFile = new File(config.getErrorDir(), code + ".html");
            if (errFile.exists()) {
                try {
                    byte[] content = Files.readAllBytes(errFile.toPath());
                    res.setHeader("Content-Type", "text/html");
                    res.setHeader("Content-Length", String.valueOf(content.length));
                    res.setBody(content);
                    return;
                } catch (IOException ignored) {}
            }

            String html = "<html><head><title>" + code + " " + text + "</title></head>" +
                          "<body><h1>" + code + " " + text + "</h1><hr>Japache Server</body></html>";
            byte[] bytes = html.toString().getBytes(StandardCharsets.UTF_8);
            res.setHeader("Content-Type", "text/html");
            res.setHeader("Content-Length", String.valueOf(bytes.length));
            res.setBody(bytes);
        }
    }

    static class HttpRequest {
        private String method;
        private String uri;
        private String version;
        private Map<String, String> headers = new HashMap<>();
        private String path;
        private Map<String, String> queryParams = new HashMap<>();

        public static HttpRequest parse(InputStream in) throws IOException {
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String line = br.readLine();
            if (line == null || line.isEmpty()) return null;

            HttpRequest req = new HttpRequest();
            String[] requestLine = line.split(" ");
            if (requestLine.length < 3) return null;

            req.method = requestLine[0];
            req.uri = requestLine[1];
            req.version = requestLine[2];

            parseUri(req);

            while ((line = br.readLine()) != null && !line.isEmpty()) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    req.headers.put(parts[0].trim(), parts[1].trim());
                }
            }
            return req;
        }

        private static void parseUri(HttpRequest req) {
            if (req.uri.contains("?")) {
                String[] parts = req.uri.split("\\?", 2);
                req.path = parts[0];
                String query = parts[1];
                for (String param : query.split("&")) {
                    String[] kv = param.split("=", 2);
                    if (kv.length == 2) {
                        req.queryParams.put(kv[0], kv[1]);
                    }
                }
            } else {
                req.path = req.uri;
            }
        }

        public String getMethod() { return method; }
        public String getUri() { return uri; }
        public String getVersion() { return version; }
        public String getPath() { return path; }
    }

    static class HttpResponse {
        private int status = 200;
        private Map<String, String> headers = new HashMap<>();
        private byte[] body = new byte[0];

        public HttpResponse() {
            headers.put("Server", "Japache/1.0");
            headers.put("Connection", "close");
            headers.put("Date", getServerTime());
        }

        private String getServerTime() {
            return DateTimeFormatter.RFC_1123_DATE_TIME.format(LocalDateTime.now().atZone(ZoneId.of("GMT")));
        }

        public void setStatus(int status) { this.status = status; }
        public void setHeader(String k, String v) { headers.put(k, v); }
        public void setBody(byte[] body) { this.body = body; }
        public int getStatus() { return status; }
        public int getContentLength() { return body.length; }

        public void write(OutputStream out) throws IOException {
            PrintWriter pw = new PrintWriter(out, false); // No auto-flush yet
            pw.printf("HTTP/1.1 %d %s\r\n", status, HttpStatus.getReason(status));
            for (Map.Entry<String, String> e : headers.entrySet()) {
                pw.printf("%s: %s\r\n", e.getKey(), e.getValue());
            }
            pw.print("\r\n");
            pw.flush();
            if (body != null && body.length > 0) {
                out.write(body);
            }
        }
    }

    static class HttpStatus {
        private static final Map<Integer, String> reasons = new HashMap<>();
        static {
            reasons.put(100, "Continue");
            reasons.put(101, "Switching Protocols");
            reasons.put(200, "OK");
            reasons.put(201, "Created");
            reasons.put(202, "Accepted");
            reasons.put(203, "Non-Authoritative Information");
            reasons.put(204, "No Content");
            reasons.put(205, "Reset Content");
            reasons.put(206, "Partial Content");
            reasons.put(300, "Multiple Choices");
            reasons.put(301, "Moved Permanently");
            reasons.put(302, "Found");
            reasons.put(303, "See Other");
            reasons.put(304, "Not Modified");
            reasons.put(305, "Use Proxy");
            reasons.put(307, "Temporary Redirect");
            reasons.put(400, "Bad Request");
            reasons.put(401, "Unauthorized");
            reasons.put(402, "Payment Required");
            reasons.put(403, "Forbidden");
            reasons.put(404, "Not Found");
            reasons.put(405, "Method Not Allowed");
            reasons.put(406, "Not Acceptable");
            reasons.put(407, "Proxy Authentication Required");
            reasons.put(408, "Request Timeout");
            reasons.put(409, "Conflict");
            reasons.put(410, "Gone");
            reasons.put(411, "Length Required");
            reasons.put(412, "Precondition Failed");
            reasons.put(413, "Request Entity Too Large");
            reasons.put(414, "Request-URI Too Long");
            reasons.put(415, "Unsupported Media Type");
            reasons.put(416, "Requested Range Not Satisfiable");
            reasons.put(417, "Expectation Failed");
            reasons.put(500, "Internal Server Error");
            reasons.put(501, "Not Implemented");
            reasons.put(502, "Bad Gateway");
            reasons.put(503, "Service Unavailable");
            reasons.put(504, "Gateway Timeout");
            reasons.put(505, "HTTP Version Not Supported");
        }
        public static String getReason(int code) {
            return reasons.getOrDefault(code, "Unknown Status");
        }
    }

    static class MimeTypes {
        private static final Map<String, String> map = new HashMap<>();
        static {
            map.put("html", "text/html");
            map.put("htm", "text/html");
            map.put("css", "text/css");
            map.put("js", "application/javascript");
            map.put("json", "application/json");
            map.put("txt", "text/plain");
            map.put("xml", "application/xml");
            map.put("jpg", "image/jpeg");
            map.put("jpeg", "image/jpeg");
            map.put("png", "image/png");
            map.put("gif", "image/gif");
            map.put("ico", "image/x-icon");
            map.put("svg", "image/svg+xml");
            map.put("pdf", "application/pdf");
            map.put("zip", "application/zip");
            map.put("tar", "application/x-tar");
            map.put("gz", "application/gzip");
            map.put("mp3", "audio/mpeg");
            map.put("wav", "audio/wav");
            map.put("mp4", "video/mp4");
            map.put("avi", "video/x-msvideo");
            map.put("mkv", "video/x-matroska");
            map.put("mov", "video/quicktime");
            map.put("wmv", "video/x-ms-wmv");
            map.put("flv", "video/x-flv");
            map.put("webm", "video/webm");
            map.put("ogg", "audio/ogg");
            map.put("oga", "audio/ogg");
            map.put("ogv", "video/ogg");
            map.put("ogx", "application/ogg");
            map.put("aac", "audio/aac");
            map.put("webp", "image/webp");
            map.put("tif", "image/tiff");
            map.put("tiff", "image/tiff");
            map.put("bmp", "image/bmp");
            map.put("csv", "text/csv");
            map.put("rtf", "application/rtf");
            map.put("doc", "application/msword");
            map.put("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
            map.put("xls", "application/vnd.ms-excel");
            map.put("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
            map.put("ppt", "application/vnd.ms-powerpoint");
            map.put("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation");
            map.put("odt", "application/vnd.oasis.opendocument.text");
            map.put("ods", "application/vnd.oasis.opendocument.spreadsheet");
            map.put("eot", "application/vnd.ms-fontobject");
            map.put("ttf", "font/ttf");
            map.put("woff", "font/woff");
            map.put("woff2", "font/woff2");
            map.put("otf", "font/otf");
            map.put("wasm", "application/wasm");
            map.put("xhtml", "application/xhtml+xml");
            map.put("class", "application/java-vm");
            map.put("jar", "application/java-archive");
            map.put("sh", "application/x-sh");
            map.put("bat", "application/x-msdos-program");
            map.put("exe", "application/x-msdos-program");
            map.put("pl", "application/x-perl");
            map.put("py", "application/x-python");
            map.put("php", "application/x-httpd-php");
            map.put("java", "text/x-java-source");
            map.put("c", "text/x-c");
            map.put("cpp", "text/x-c++");
            map.put("h", "text/x-c-header");
            map.put("cs", "text/x-csharp");
            map.put("swift", "text/x-swift");
            map.put("go", "text/x-go");
            map.put("rb", "application/x-ruby");
            map.put("rs", "text/rust");
            map.put("ts", "application/typescript");
            map.put("tsx", "application/typescript");
            map.put("vue", "text/x-vue");
            map.put("sql", "application/sql");
            map.put("md", "text/markdown");
            map.put("yaml", "text/yaml");
            map.put("yml", "text/yaml");
            map.put("ini", "text/plain");
            map.put("conf", "text/plain");
            map.put("log", "text/plain");
            map.put("properties", "text/plain");
        }

        public static String get(String filename) {
            int dot = filename.lastIndexOf(".");
            if (dot == -1) return "application/octet-stream";
            String ext = filename.substring(dot + 1).toLowerCase();
            return map.getOrDefault(ext, "application/octet-stream");
        }
    }

    public static class StringUtils {
        public static boolean isEmpty(String s) {
            return s == null || s.length() == 0;
        }

        public static String padLeft(String s, int n) {
            return String.format("%" + n + "s", s);
        }

        public static String padRight(String s, int n) {
            return String.format("%-" + n + "s", s);
        }
    }

    public static class NetUtils {
        public static boolean isIpV4(String ip) {
            try {
                if ( ip == null || ip.isEmpty() ) {
                    return false;
                }
                String[] parts = ip.split( "\\." );
                if ( parts.length != 4 ) {
                    return false;
                }
                for ( String s : parts ) {
                    int i = Integer.parseInt( s );
                    if ( (i < 0) || (i > 255) ) {
                        return false;
                    }
                }
                if ( ip.endsWith(".") ) {
                    return false;
                }
                return true;
            } catch (NumberFormatException nfe) {
                return false;
            }
        }
    }

    public static class HtmlBuilder {
        private StringBuilder sb = new StringBuilder();

        public HtmlBuilder startHtml(String title) {
            sb.append("<!DOCTYPE html><html><head><title>").append(title).append("</title>");
            sb.append("<style>body{font-family:sans-serif;} hr{border:0;border-top:1px solid #ccc;}</style>");
            sb.append("</head><body>");
            return this;
        }

        public HtmlBuilder h1(String text) {
            sb.append("<h1>").append(text).append("</h1>");
            return this;
        }

        public HtmlBuilder hr() {
            sb.append("<hr>");
            return this;
        }

        public HtmlBuilder p(String text) {
            sb.append("<p>").append(text).append("</p>");
            return this;
        }

        public HtmlBuilder endHtml() {
            sb.append("</body></html>");
            return this;
        }

        public String build() {
            return sb.toString();
        }
    }

    public static class DateUtils {
        public static String now() {
             return DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(LocalDateTime.now());
        }
    }

    public static class ConfigValidator {
        public static boolean validatePort(int port) {
            return port > 0 && port < 65535;
        }

        public static boolean validateDir(String path) {
            File f = new File(path);
            return f.exists() && f.isDirectory();
        }
    }

    static class ByteUtils {
        public static byte[] combine(byte[] one, byte[] two) {
            byte[] combined = new byte[one.length + two.length];
            System.arraycopy(one, 0, combined, 0, one.length);
            System.arraycopy(two, 0, combined, one.length, two.length);
            return combined;
        }
    }

    static class SecurityContext {
         private String user;
         private List<String> roles;

         public SecurityContext(String user) {
             this.user = user;
             this.roles = new ArrayList<>();
         }

         public void addRole(String role) {
             this.roles.add(role);
         }

         public boolean hasRole(String role) {
             return roles.contains(role);
         }
    }

    static class Session {
        private String id;
        private long creationTime;
        private Map<String, Object> attributes = new HashMap<>();

        public Session(String id) {
            this.id = id;
            this.creationTime = System.currentTimeMillis();
        }

        public void setAttribute(String key, Object val) {
            attributes.put(key, val);
        }

        public Object getAttribute(String key) {
            return attributes.get(key);
        }
    }

    static class CacheManager {
        private static Map<String, byte[]> memoryCache = new HashMap<>();

        public static void put(String key, byte[] data) {
            if (memoryCache.size() > 1000) memoryCache.clear();
            memoryCache.put(key, data);
        }

        public static byte[] get(String key) {
            return memoryCache.get(key);
        }

        public static void clear() {
            memoryCache.clear();
        }
    }
}
