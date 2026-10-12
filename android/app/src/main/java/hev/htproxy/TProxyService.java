package hev.htproxy;

public final class TProxyService {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    private TProxyService() {
    }

    public static native boolean TProxyStartService(String configPath, int tunFd);

    public static native boolean TProxyStopService();

    public static native boolean TProxyIsRunning();

    public static native long[] TProxyGetStats();

    public static native void TProxySetBlockedIps(String[] addresses);

    public static native boolean TProxyBlockDomain(String domain);

    private static native void addDynamicSniRule(String domain);
    public static native boolean TProxySetDynamicSniAllowlist(String[] domains);

    public static boolean TProxyAddDynamicSniRule(String domain) {
        if (domain == null || domain.trim().isEmpty() || !TProxyIsRunning()) {
            return false;
        }
        addDynamicSniRule(domain);
        return true;
    }

    public static boolean protectSocket(int socketFd) {
        return com.ciberdefensa.aura.AuraVpnService.protectSocket(socketFd);
    }

    public static void dispatchDnsEvent(
            String domain, int action, String sourceAddress, int sourcePort) {
        com.ciberdefensa.aura.AuraNetworkStream.INSTANCE.emitDnsEvent(
                domain, action, sourceAddress, sourcePort);
    }

    public static void dispatchSniEvent(
            String domain, String destinationAddress, int destinationPort) {
        com.ciberdefensa.aura.AuraNetworkStream.INSTANCE.emitSniEvent(
                domain, destinationAddress, destinationPort);
    }

    public static void dispatchEncryptedDnsEvent(
            String destinationAddress, int destinationPort, String transportProtocol) {
        com.ciberdefensa.aura.AuraNetworkStream.INSTANCE.emitEncryptedDnsEvent(
                destinationAddress, destinationPort, transportProtocol);
    }
}