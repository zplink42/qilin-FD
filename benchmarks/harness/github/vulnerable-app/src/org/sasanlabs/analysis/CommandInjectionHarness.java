package org.sasanlabs.analysis;

import org.sasanlabs.service.vulnerability.commandInjection.CommandInjection;

public final class CommandInjectionHarness {
    private CommandInjectionHarness() {
    }

    public static void main(String[] args) throws Exception {
        // A standalone model for the @RequestParam("ipaddress") external web value.
        String requestIpAddress = System.getenv("ipaddress");
        new CommandInjection().getVulnerablePayloadLevel1(requestIpAddress);
    }
}
