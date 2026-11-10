package app.keystone.job;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import org.jboss.logging.Logger;

@Named("keystoneJob")
@ApplicationScoped
public class SystemJobTasks {
    private static final Logger LOG = Logger.getLogger(SystemJobTasks.class);

    @JobTask(name = "Keystone heartbeat", group = "system", description = "Writes a diagnostic heartbeat to the application log")
    public void heartbeat() {
        LOG.info("keystone scheduled job heartbeat");
    }
}
