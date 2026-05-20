package com.dpi.types;

/**
 * Application type enumeration
 * Used to classify connections by application/service
 */
public enum AppType {
    UNKNOWN(0, "Unknown"),
    HTTP(1, "HTTP"),
    HTTPS(2, "HTTPS"),
    DNS(3, "DNS"),
    TLS(4, "TLS"),
    QUIC(5, "QUIC"),
    
    // Specific applications (detected via SNI)
    GOOGLE(10, "Google"),
    FACEBOOK(11, "Facebook"),
    YOUTUBE(12, "YouTube"),
    TWITTER(13, "Twitter/X"),
    INSTAGRAM(14, "Instagram"),
    NETFLIX(15, "Netflix"),
    AMAZON(16, "Amazon"),
    MICROSOFT(17, "Microsoft"),
    APPLE(18, "Apple"),
    WHATSAPP(19, "WhatsApp"),
    TELEGRAM(20, "Telegram"),
    TIKTOK(21, "TikTok"),
    SPOTIFY(22, "Spotify"),
    ZOOM(23, "Zoom"),
    DISCORD(24, "Discord"),
    GITHUB(25, "GitHub"),
    CLOUDFLARE(26, "Cloudflare");

    private final int value;
    private final String displayName;

    AppType(int value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public int getValue() { return value; }
    public String getDisplayName() { return displayName; }

    public static AppType fromValue(int value) {
        for (AppType type : AppType.values()) {
            if (type.value == value) return type;
        }
        return UNKNOWN;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
