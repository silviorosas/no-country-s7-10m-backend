package s710m.noCountry.server.configException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class HandlerException extends ResponseEntityExceptionHandler {

    @ExceptionHandler(value = {EntityNotFoundException.class})
    protected ResponseEntity<Object> handleNotFound(EntityNotFoundException ex, WebRequest request) {
        String response = ex.getMessage();
        return handleExceptionInternal(ex, response, new HttpHeaders(), HttpStatus.NOT_FOUND ,request);
    }

    @ExceptionHandler(value = {EntityFoundException.class})
    protected ResponseEntity<Object> handleFound(EntityFoundException ex, WebRequest request) {
        String response = ex.getMessage();
        return handleExceptionInternal(ex, response, new HttpHeaders(), HttpStatus.BAD_REQUEST ,request);
    }

    protected ResponseEntity<Map<String,String>> handleInvalidArgument(MethodArgumentNotValidException ex) {
        Map<String,String> errorMap = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach( error -> {
                    errorMap.put(ex.getFieldError().getField(), error.getDefaultMessage());
                }
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMap);
    }
}
