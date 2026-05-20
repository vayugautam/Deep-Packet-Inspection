package com.dpi.types;

import java.util.Arrays;

/**
 * Application type detection from SNI
 */
public class AppTypeDetector {

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return AppType.UNKNOWN;
        }

        String lower = sni.toLowerCase();

        // Google
        if (lower.contains("google") || lower.contains("gstatic") ||
            lower.contains("googleapis") || lower.contains("ggpht") ||
            lower.contains("gvt1")) {
            return AppType.GOOGLE;
        }

        // YouTube
        if (lower.contains("youtube") || lower.contains("ytimg") ||
            lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }

        // Facebook/Meta
        if (lower.contains("facebook") || lower.contains("fbcdn") ||
            lower.contains("fb.com") || lower.contains("fbsbx") ||
            lower.contains("meta.com")) {
            return AppType.FACEBOOK;
        }

        // Instagram
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }

        // Twitter
        if (lower.contains("twitter") || lower.contains("t.co") ||
            lower.contains("twimg")) {
            return AppType.TWITTER;
        }

        // Netflix
        if (lower.contains("netflix") || lower.contains("nflxext") ||
            lower.contains("nflxso")) {
            return AppType.NETFLIX;
        }

        // Amazon
        if (lower.contains("amazon") || lower.contains("amzn") ||
            lower.contains("aws")) {
            return AppType.AMAZON;
        }

        // Microsoft
        if (lower.contains("microsoft") || lower.contains("msft") ||
            lower.contains("office") || lower.contains("azure")) {
            return AppType.MICROSOFT;
        }

        // Apple
        if (lower.contains("apple") || lower.contains("icloud") ||
            lower.contains("itunes")) {
            return AppType.APPLE;
        }

        // WhatsApp
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return AppType.WHATSAPP;
        }

        // Telegram
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return AppType.TELEGRAM;
        }

        // TikTok
        if (lower.contains("tiktok") || lower.contains("bytedance")) {
            return AppType.TIKTOK;
        }

        // Spotify
        if (lower.contains("spotify")) {
            return AppType.SPOTIFY;
        }

        // Zoom
        if (lower.contains("zoom")) {
            return AppType.ZOOM;
        }

        // Discord
        if (lower.contains("discord")) {
            return AppType.DISCORD;
        }

        // GitHub
        if (lower.contains("github")) {
            return AppType.GITHUB;
        }

        // Cloudflare
        if (lower.contains("cloudflare")) {
            return AppType.CLOUDFLARE;
        }

        return AppType.UNKNOWN;
    }
}
