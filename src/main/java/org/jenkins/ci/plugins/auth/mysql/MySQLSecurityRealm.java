package org.jenkins.ci.plugins.auth.mysql;

import org.jenkins.ci.plugins.auth.mysql.crypt.EncryptionException;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import jenkins.model.GlobalConfiguration;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jenkinsci.plugins.database.Database;
import org.jenkinsci.plugins.database.GlobalDatabaseConfiguration;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.jenkins.ci.plugins.auth.mysql.crypt.Cipher;

/**
 * @author tiger
 */
public class MySQLSecurityRealm extends AbstractPasswordBasedSecurityRealm {

    @DataBoundConstructor
    public MySQLSecurityRealm(String sql, String encryption, Integer hashTimes, String salt) {

        this.sql = Util.fixEmptyAndTrim(sql);
        this.encryption = encryption;
        this.hashTimes = hashTimes;
        this.salt = Util.fixEmptyAndTrim(salt);


    }

    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getHelpFile() {
            return "/plugin/mysql-auth/help/overview.html";
        }

        @Override
        public String getDisplayName() {
//            return Messages.DisplayName();
            return "MYSQL";
        }
    }

    @Extension
    public static DescriptorImpl install() {
        return new DescriptorImpl();
    }


    @Override
    protected UserDetails authenticate(String username, String password)
            throws AuthenticationException {
        UserDetails userDetails = loadUserByUsername(username);

        LOGGER.info("salt="+salt+"##hash="+hashTimes+"##encryption="+encryption+"##sql="+sql);

        String storedPassword = userDetails.getPassword();
        Cipher cipher;
        if (encryption.equals(Cipher.CRYPT)) {
            String salt = storedPassword.substring(0, 2);
            cipher = new Cipher(encryption, salt);
        } else {
            if (this.salt != null && !"".equals(salt)) {
                cipher = new Cipher(encryption, username + salt);
            } else {
                cipher = new Cipher(encryption);
            }
        }
        String encryptedPassword = null;
        try {
            encryptedPassword = cipher.encode(password.trim(), this.hashTimes);
        } catch (EncryptionException e) {
            LOGGER.warning("cipher encode failure!!!" + e.getLocalizedMessage());
        }
        LOGGER.info("Encrypted Password: " + encryptedPassword);
        LOGGER.info("Stored Password: " + storedPassword);
        if (!storedPassword.equals(encryptedPassword)) {
            LOGGER.warning("MySQLSecurity: Invalid Username or Password");
            throw new BadCredentialsException("Invalid Username or Password");
        } else {
            // Password is valid.  Build UserDetail
            Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
            userDetails = new MySQLUserDetail(username, encryptedPassword,
                    true, true, true, true,
                    groups.toArray(new GrantedAuthority[groups.size()]));
        }

        return userDetails;
    }

    /**
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {


        UserDetails user = null;
        if (username == null || "".equals(username.trim())) {
            throw new UsernameNotFoundException("Username is empty");
        }
//        String connectionString;
//
//        connectionString = "jdbc:mysql://" + myServer + "/" +
//                myDatabase;
//        LOGGER.info("MySQLSecurity: Connection String - " + connectionString);
        Connection conn = null;
        try {

            Database database =
                    GlobalConfiguration.all().get(GlobalDatabaseConfiguration.class).getDatabase();

            // Connect to the database
//            Class.forName("com.mysql.jdbc.Driver").newInstance();
//            conn = DriverManager.getConnection(connectionString,
//                    myUsername, myPassword);
            if(database == null || database.getDataSource() == null || database.getDataSource().getConnection() == null){
                LOGGER.warning("Database: check database configuration");
                throw new BadCredentialsException("Please check your database info");
            }

            conn = database.getDataSource().getConnection();



            LOGGER.fine("MySQLSecurity: Connection established.");

            PreparedStatement statement = conn.prepareStatement(sql);

            statement.setString(1, username);
            ResultSet results = statement.executeQuery();
            LOGGER.fine("MySQLSecurity: Query executed.");

            // Grab the first result (should be only user returned)
            if (results.first()) {
                // Build the user detail
                Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
                groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
                user = new MySQLUserDetail(username, results.getString(2),
                        true, true, true, true,
                        groups.toArray(new GrantedAuthority[groups.size()]));
            } else {
                LOGGER.warning("MySQLSecurity: Invalid Username or Password");
                throw new UsernameNotFoundException("MySQL: User not found");
            }
        } catch (SQLException e) {
            LOGGER.warning("MySQLSecurity Realm Error: " + e.getLocalizedMessage());
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                    LOGGER.fine("MySQLSecurity: Connection closed.");
                } catch (Exception ex) {
                    /** Ignore any errors **/
                }
            }
        }
        return user;
    }

    /**
     * @param groupname
     * @return
     * @throws UsernameNotFoundException
     * @throws DataAccessException
     */
    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
            throws UsernameNotFoundException, DataAccessException {
        LOGGER.warning("ERROR: Group lookup is not supported.");
        throw new UsernameNotFoundException("MySQLSecurityRealm: Non-supported function");
    }

//    class Authenticator extends AbstractUserDetailsAuthenticationProvider {
//
//        @Override
//        protected void additionalAuthenticationChecks(UserDetails userDetails,
//                                                      UsernamePasswordAuthenticationToken authentication)
//                throws AuthenticationException {
//            // Assumed to be done in the retrieveUser method
//        }
//
//        @Override
//        protected UserDetails retrieveUser(String username,
//                                           UsernamePasswordAuthenticationToken authentication)
//                throws AuthenticationException {
//            return MySQLSecurityRealm.this.authenticate(username,
//                    authentication.getCredentials().toString());
//        }
//
//    }

    /**
     * Logger for debugging purposes.
     */
    private static final Logger LOGGER =
            Logger.getLogger(MySQLSecurityRealm.class.getName());

    /**
     * sql for query a user from database
     */
    private String sql;

    /**
     * Encryption type used for the password
     */
    private String encryption;

    /**
     * salf for Encryption method
     */
    private String salt;

    /**
     * Encryption times used for the password
     */
    private Integer hashTimes;


    public String getSql() {
        return sql;
    }

    public void setSql(String sql) {
        this.sql = sql;
    }

    public String getEncryption() {
        return encryption;
    }

    public void setEncryption(String encryption) {
        this.encryption = encryption;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public Integer getHashTimes() {
        return hashTimes;
    }

    public void setHashTimes(Integer hashTimes) {
        this.hashTimes = hashTimes;
    }
}
