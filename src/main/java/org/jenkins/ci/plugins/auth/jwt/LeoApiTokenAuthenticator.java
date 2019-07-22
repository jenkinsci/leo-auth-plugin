package org.jenkins.ci.plugins.auth.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import hudson.Extension;
import hudson.model.User;
import jenkins.model.GlobalConfiguration;
import jenkins.security.BasicHeaderAuthenticator;
import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;

/**
 * @author tiger
 */
@Extension
public class LeoApiTokenAuthenticator extends BasicHeaderAuthenticator {

    private static final Logger LOGGER = Logger.getLogger(LeoApiTokenAuthenticator.class.getName());

    @Override
    public Authentication authenticate(HttpServletRequest req, HttpServletResponse rsp, String username, String password) throws IOException, ServletException {

//        LOGGER.log(WARNING,username+"##"+password);

        User user = User.getById(username, true);
        if (!GlobalConfiguration.all().get(LeoTokenAuthGlobalConfiguration.class).isEnabled()) {
            return null;
        }
        if (user == null) {
            return null;
        }

        if (verify(password, username, GlobalConfiguration.all().get(LeoTokenAuthGlobalConfiguration.class).getSecret().getPlainText())) {
//            LOGGER.log(WARNING,"success");
            Authentication auth;
            try {
                UserDetails userDetails = user.getUserDetailsForImpersonation();
                auth = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "", userDetails.getAuthorities());

                SecurityListener.fireAuthenticated(userDetails);

            } catch (UsernameNotFoundException x) {
                // The token was valid, but the impersonation failed. This token is clearly not his real password,
                // so there's no point in continuing the request processing. Report this error and abort.
                LOGGER.log(WARNING, "API token matched for user " + username + " but the impersonation failed", x);
                throw new ServletException(x);
            } catch (DataAccessException x) {
                throw new ServletException(x);
            }
            return auth;
        }else{
            LOGGER.log(WARNING,"verify JWT token failure");
        }

        return null;
    }

    /**
     * 校验token是否正确
     *
     * @param token  密钥
     * @param secret 用户的密码
     * @return 是否正确
     */
    public boolean verify(String token, String userName, String secret) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
//                    .withClaim("userId", userId)
                    .withClaim("userName",userName)
                    .build();
            verifier.verify(token);
            return true;
        } catch (Exception exception) {
            return false;
        }
    }
}
