import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;

public class Japache {
    private static final String CONFIG_FILE = "config.yml";
    private static final String WEBROOT_DIR = "webroot";
    private static final String ERROR_DIR = "error";
    private static final String LOG_DIR = "logs";
    private static int PORT = 8080;
    private static volatile boolean isRunning = true;
    private static ServerSocket serverSocket;
    private static PrintWriter logWriter;

    public static void main(String[] args) {
        setupEnvironment();
        startConsoleListener();
        startServer();
    }

    private static void setupEnvironment() {
        logToConsole("Démarrage de Japache...");
        createDirIfNotExists(WEBROOT_DIR);
        createDirIfNotExists(ERROR_DIR);
        createDirIfNotExists(LOG_DIR);
        initLogging();
        createFileIfNotExists(Paths.get(WEBROOT_DIR, "index.html"),
            "<html><head><title>Japache</title></head><body><h1>Bienvenue sur Japache!</h1><p>Serveur actif.</p></body></html>");
        createFileIfNotExists(Paths.get(ERROR_DIR, "404.html"), "<html><h1>404 Introuvable</h1></html>");
        createFileIfNotExists(Paths.get(ERROR_DIR, "403.html"), "<html><h1>403 Interdit</h1></html>");
        createFileIfNotExists(Paths.get(ERROR_DIR, "500.html"), "<html><h1>500 Erreur Serveur</h1></html>");

        Path configPath = Paths.get(CONFIG_FILE);
        if (!Files.exists(configPath)) {
            createFileIfNotExists(configPath, "port: 8080\n# Configuration Japache");
        } else {
            loadConfig(configPath);
        }
    }

    private static void loadConfig(Path path) {
        try {
            List<String> lines = Files.readAllLines(path);
            for (String line : lines) {
                if (line.trim().startsWith("port:")) {
                    PORT = Integer.parseInt(line.split(":")[1].trim());
                    log("Config chargée: Port " + PORT);
                }
            }
        } catch (Exception e) { log("Erreur config: " + e.getMessage()); }
    }

    private static void initLogging() {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            File logFile = new File(LOG_DIR, "japache_" + timestamp + ".log");
            logWriter = new PrintWriter(new FileWriter(logFile, true), true);
            log("Log file: " + logFile.getName());
        } catch (IOException e) { e.printStackTrace(); }
    }

    public static synchronized void log(String message) {
        String msg = "[" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "] " + message;
        System.out.println(msg);
        if (logWriter != null) logWriter.println(msg);
    }

    private static void logToConsole(String msg) { System.out.println(msg); }

    private static void startConsoleListener() {
        Thread consoleThread = new Thread(() -> {
            Scanner scanner = new Scanner(System.in);
            while (isRunning) {
                if (scanner.hasNextLine() && "stop".equalsIgnoreCase(scanner.nextLine().trim())) {
                    stopServer();
                    break;
                }
            }
        });
        consoleThread.setDaemon(true);
        consoleThread.start();
    }

    private static void stopServer() {
        log("Arrêt...");
        isRunning = false;
        try {
            if (serverSocket != null) serverSocket.close();
            if (logWriter != null) logWriter.close();
        } catch (IOException e) {}
        System.exit(0);
    }

    private static void startServer() {
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            serverSocket = new ServerSocket(PORT);
            log("Serveur pret sur le port " + PORT);
            log("Tapez 'stop' pour quitter.");
            while (isRunning) {
                try {
                    Socket client = serverSocket.accept();
                    executor.submit(new ClientHandler(client));
                } catch (Exception e) { if(isRunning) log("Erreur: " + e.getMessage()); }
            }
        } catch (IOException e) { log("Erreur fatale: " + e.getMessage()); }
    }

    private static void createDirIfNotExists(String path) { new File(path).mkdirs(); }
    private static void createFileIfNotExists(Path path, String content) {
        if (!Files.exists(path)) { try { Files.writeString(path, content); } catch (IOException e) {} }
    }

    static class ClientHandler implements Runnable {
        private Socket socket;
        public ClientHandler(Socket s) { this.socket = s; }
        public void run() {
            try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
                String line = reader.readLine();
                if (line == null) return;
                log(socket.getInetAddress().getHostAddress() + " -> " + line);
                String[] parts = line.split(" ");
                if (parts.length < 2) return;
                String path = parts[1].equals("/") ? "/index.html" : parts[1];
                if (path.contains("..")) { sendError(out, 403); return; }
                File file = new File(WEBROOT_DIR, path);
                if (!file.exists()) sendError(out, 404);
                else if (file.isDirectory()) sendError(out, 403);
                else sendFile(out, file);
            } catch (Exception e) { log("Erreur client: " + e.getMessage()); }
            finally { try { socket.close(); } catch (Exception e) {} }
        }
        private void sendFile(OutputStream out, File file) throws IOException {
            byte[] c = Files.readAllBytes(file.toPath());
            out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + c.length + "\r\n\r\n").getBytes());
            out.write(c);
        }
        private void sendError(OutputStream out, int code) throws IOException {
            File f = new File(ERROR_DIR, code + ".html");
            byte[] c = f.exists() ? Files.readAllBytes(f.toPath()) : ("<h1>Error " + code + "</h1>").getBytes();
            out.write(("HTTP/1.1 " + code + " Error\r\nContent-Length: " + c.length + "\r\n\r\n").getBytes());
            out.write(c);
        }
    }
}
