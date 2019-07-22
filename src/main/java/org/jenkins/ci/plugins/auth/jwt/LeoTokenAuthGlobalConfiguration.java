package org.jenkins.ci.plugins.auth.jwt;

import hudson.Extension;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.util.logging.Logger;

@Extension
public class LeoTokenAuthGlobalConfiguration extends GlobalConfiguration {
    private static final Logger LOGGER = Logger.getLogger(LeoTokenAuthGlobalConfiguration.class.getName());

    private boolean enabled = false;

    private Secret secret;

    public LeoTokenAuthGlobalConfiguration() {
        this.load();
    }

//    public LeoTokenAuthGlobalConfiguration(boolean enabled, String secret) {
//        this.enabled = enabled;
//        this.secret = secret;
//    }

    @Override
    @Nonnull
    public String getDisplayName() {
        return "LEO Jenkins Token Auth";
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) {
        req.bindJSON(this, json);
        this.save();
        return true;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    @DataBoundSetter
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Secret getSecret() {
        return secret;
    }

    @DataBoundSetter
    public void setSecret(Secret secret) {
        this.secret = secret;
    }
}
