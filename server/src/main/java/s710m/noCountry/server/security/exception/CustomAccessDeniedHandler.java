package s710m.noCountry.server.security.exception;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    public static final Logger LOG
            = Logger.getLogger("CustomAccessDeniedHandler");

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.addHeader("Authenticate", "required-authentication");
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        LOG.warning("HTTP Status 403 - " + accessDeniedException.getMessage());
    }
}
