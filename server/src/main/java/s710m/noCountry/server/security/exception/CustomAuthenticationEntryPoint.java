package s710m.noCountry.server.security.exception;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    public static final Logger LOG
            = Logger.getLogger("CustomAuthenticationEntryPoint");

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.addHeader("Authenticate", "invalid-authentication");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access denied");
        LOG.warning("HTTP Status 401 - " + authException.getMessage());
    }
}
