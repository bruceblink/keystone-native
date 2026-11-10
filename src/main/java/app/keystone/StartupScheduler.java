package app.keystone;

import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

@ApplicationScoped
public class StartupScheduler {
    private static final Logger LOG = Logger.getLogger(StartupScheduler.class);
    @Scheduled(every = "15m", identity = "keystone-heartbeat")
    void heartbeat() { LOG.debug("keystone-native scheduler heartbeat"); }
}
