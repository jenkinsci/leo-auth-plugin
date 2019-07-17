package org.jenkins.ci.plugins.database.mysql;

import hudson.Extension;
import hudson.util.Secret;
import org.jenkinsci.plugins.database.AbstractRemoteDatabase;
import org.jenkinsci.plugins.database.AbstractRemoteDatabaseDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;

/**
 * @author tiger
 */
public class MysqlDatabase extends AbstractRemoteDatabase {
    @DataBoundConstructor
    public MysqlDatabase(String hostname, String database, String username, Secret password, String properties) {
        super(hostname, database, username, password, properties);
    }

    @Override
    protected Class<com.mysql.jdbc.Driver> getDriverClass() {
        return com.mysql.jdbc.Driver.class;
    }

    @Override
    protected String getJdbcUrl() {
        return "jdbc:mysql://" + hostname + '/' + database;
    }

    @Extension
    public static class DescriptorImpl extends AbstractRemoteDatabaseDescriptor {

        @Nonnull
        @Override
        public String getDisplayName() {
            return "MySQL";
        }

    }
}
