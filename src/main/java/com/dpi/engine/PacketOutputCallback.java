package com.dpi.engine;

import com.dpi.types.PacketAction;
import com.dpi.types.PacketJob;

/**
 * Callback interface invoked when a packet is processed and ready for output
 */
@FunctionalInterface
public interface PacketOutputCallback {
    void handleOutput(PacketJob job, PacketAction action);
}
