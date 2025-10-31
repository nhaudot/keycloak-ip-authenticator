package io.github.nhaudot.keycloak.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.authentication.AuthenticationFlowError;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IpAutoLoginAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(IpAutoLoginAuthenticator.class);

    private static Map<String, String> ipUserMap = new HashMap<>();
    private static String currentFilePath = null;
    private static final String DEFAULT_FILE_PATH = "/opt/keycloak/data/ip-user-list.properties";

    // Load IP → user mapping from file
    private static void loadIpUserMap(String filePath) {
        if (!ipUserMap.isEmpty() && filePath.equals(currentFilePath)) return; // already loaded for this path

        ipUserMap.clear();
        currentFilePath = filePath;

        try {
            List<String> lines = Files.readAllLines(Paths.get(filePath));
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty() || !line.contains("=")) continue;
                String[] parts = line.split("=", 2);
                String ip = parts[0].trim();
                String username = parts[1].trim();
                if (!ipUserMap.containsKey(ip)) {
                    ipUserMap.put(ip, username);
                } else {
                    logger.warnf("Duplicate IP entry ignored: %s -> %s", ip, username);
                }
            }
            logger.infof("Loaded %d IP mappings from %s", ipUserMap.size(), filePath);
        } catch (IOException e) {
            logger.errorf(e, "Failed to load IP-user mapping from file: %s", filePath);
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Get file path from config if provided
        String filePath = context.getAuthenticatorConfig() != null
                ? context.getAuthenticatorConfig().getConfig().get("ipUserMappingFile")
                : null;

        if (filePath == null || filePath.trim().isEmpty()) {
            filePath = DEFAULT_FILE_PATH;
        }

        loadIpUserMap(filePath);
        String clientIp = context.getConnection().getRemoteAddr();
        String username = ipUserMap.get(clientIp);

        if (username != null) {
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
            if (user != null) {
                context.setUser(user);
                context.success();
                logger.infof("IP %s automatically authenticated as user %s", clientIp, username);
                return;
            } else {
                logger.warnf("User %s not found for IP %s", username, clientIp);
            }
        } else {
            logger.debugf("No mapping found for IP %s", clientIp);
        }
        context.failure(AuthenticationFlowError.INVALID_USER);
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
