package com.dpi;

import com.dpi.engine.RuleManager;
import com.dpi.types.AppType;
import org.junit.Before;
import org.junit.Test;
import java.io.File;
import java.io.IOException;
import java.util.Optional;
import static org.junit.Assert.*;

public class RuleManagerTest {
    private RuleManager ruleManager;

    @Before
    public void setUp() {
        ruleManager = new RuleManager();
    }

    @Test
    public void testBlockIP() {
        ruleManager.blockIP("192.168.1.50");
        Optional<RuleManager.BlockReason> blockReason = ruleManager.shouldBlock(
            0xC0A80132L, // 192.168.1.50
            80,
            AppType.UNKNOWN,
            ""
        );
        assertTrue(blockReason.isPresent());
        assertEquals("Blocked Source IP", blockReason.get().getReason());

        Optional<RuleManager.BlockReason> cleanReason = ruleManager.shouldBlock(
            0xC0A80133L, // 192.168.1.51
            80,
            AppType.UNKNOWN,
            ""
        );
        assertFalse(cleanReason.isPresent());
    }

    @Test
    public void testBlockApp() {
        ruleManager.blockApp(AppType.YOUTUBE);
        Optional<RuleManager.BlockReason> blockReason = ruleManager.shouldBlock(
            0xC0A80132L,
            443,
            AppType.YOUTUBE,
            "youtube.com"
        );
        assertTrue(blockReason.isPresent());
        assertEquals("Blocked Application (YouTube)", blockReason.get().getReason());
    }

    @Test
    public void testBlockDomain() {
        ruleManager.blockDomain("*.facebook.com");
        Optional<RuleManager.BlockReason> blockReason = ruleManager.shouldBlock(
            0xC0A80132L,
            443,
            AppType.FACEBOOK,
            "sub.facebook.com"
        );
        assertTrue(blockReason.isPresent());
        assertEquals("Blocked Domain", blockReason.get().getReason());

        Optional<RuleManager.BlockReason> bareReason = ruleManager.shouldBlock(
            0xC0A80132L,
            443,
            AppType.FACEBOOK,
            "facebook.com"
        );
        assertTrue(bareReason.isPresent());

        Optional<RuleManager.BlockReason> nonMatchingReason = ruleManager.shouldBlock(
            0xC0A80132L,
            443,
            AppType.GOOGLE,
            "google.com"
        );
        assertFalse(nonMatchingReason.isPresent());
    }

    @Test
    public void testBlockPort() {
        ruleManager.blockPort(8080);
        Optional<RuleManager.BlockReason> blockReason = ruleManager.shouldBlock(
            0xC0A80132L,
            8080,
            AppType.UNKNOWN,
            ""
        );
        assertTrue(blockReason.isPresent());
        assertEquals("Blocked Port", blockReason.get().getReason());
    }

    @Test
    public void testSerialization() throws IOException {
        ruleManager.blockIP("10.0.0.1");
        ruleManager.blockApp(AppType.TIKTOK);
        ruleManager.blockDomain("*.tiktok.com");
        ruleManager.blockPort(9999);

        File tempFile = File.createTempFile("rules", ".txt");
        tempFile.deleteOnExit();

        assertTrue(ruleManager.saveRules(tempFile.getAbsolutePath()));

        RuleManager loadedManager = new RuleManager();
        assertTrue(loadedManager.loadRules(tempFile.getAbsolutePath()));

        Optional<RuleManager.BlockReason> blockIpReason = loadedManager.shouldBlock(
            0x0A000001L, // 10.0.0.1
            80,
            AppType.UNKNOWN,
            ""
        );
        assertTrue(blockIpReason.isPresent());

        Optional<RuleManager.BlockReason> blockAppReason = loadedManager.shouldBlock(
            0xC0A80101L,
            443,
            AppType.TIKTOK,
            "tiktok.com"
        );
        assertTrue(blockAppReason.isPresent());

        Optional<RuleManager.BlockReason> blockPortReason = loadedManager.shouldBlock(
            0xC0A80101L,
            9999,
            AppType.UNKNOWN,
            ""
        );
        assertTrue(blockPortReason.isPresent());
    }
}
